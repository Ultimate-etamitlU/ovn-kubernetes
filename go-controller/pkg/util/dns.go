// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
)

const (
	// defaultMinTTL is the minimum TTL value that will be used for a domain name if an invalid or zero TTL is found
	defaultMinTTL = 5 * time.Second
	// defaultMaxTTL is the maximum TTL value that will be used for a domain name if an invalid or zero TTL is found
	defaultMaxTTL = 2 * time.Minute
	// maxRetryBeforeBackoff is the maximum number of times to retry a DNS lookup before exponential backoff starts
	maxRetryBeforeBackoff = 10
)

type dnsValue struct {
	// All IP addresses for a given domain name
	ips []net.IP
	// Time-to-live value from non-authoritative/cached name server for the domain
	ttl time.Duration
	// Holds (last dns lookup time + ttl), tells when to refresh IPs next time
	nextQueryTime time.Time
	// Number of times the DNS lookup has been retried before backoff starts
	retryCount int
}

// DNS tracks DNS names, their resolved IP addresses, and refresh times.
type DNS struct {
	// Protects dnsMap operations
	lock sync.Mutex
	// Holds dns name and its corresponding information
	dnsMap map[string]dnsValue

	// DNS resolvers
	nameservers []string
	// DNS port
	port string
}

// NewDNS creates a resolver using nameservers from resolverConfigFile.
func NewDNS(resolverConfigFile string) (*DNS, error) {
	config, err := dnsOps.ClientConfigFromFile(resolverConfigFile)
	if err != nil || config == nil {
		return nil, fmt.Errorf("cannot initialize the resolver: %v", err)
	}

	return &DNS{
		dnsMap:      map[string]dnsValue{},
		nameservers: filterIPServers(config.Servers),
		port:        config.Port,
	}, nil
}

// Size returns the number of DNS names currently tracked by d.
func (d *DNS) Size() int {
	d.lock.Lock()
	defer d.lock.Unlock()

	return len(d.dnsMap)
}

// GetIPs returns the currently resolved IP addresses for dns.
func (d *DNS) GetIPs(dns string) []net.IP {
	d.lock.Lock()
	defer d.lock.Unlock()

	data := dnsValue{}
	if res, ok := d.dnsMap[dns]; ok {
		data.ips = make([]net.IP, len(res.ips))
		copy(data.ips, res.ips)
	}
	return data.ips
}

// Add begins tracking dns and resolves its initial IP addresses.
func (d *DNS) Add(dns string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.dnsMap[dns] = dnsValue{}
	_, err := d.updateOne(dns)
	if err != nil {
		delete(d.dnsMap, dns)
	}
	return err
}

// Delete stops tracking dns.
func (d *DNS) Delete(dns string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	delete(d.dnsMap, dns)
}

// Update re-resolves dnsName and reports whether its IP set changed.
func (d *DNS) Update(dnsName string) (bool, error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.updateOne(dnsName)
}

func (d *DNS) updateOne(dns string) (bool, error) {
	res, ok := d.dnsMap[dns]
	if !ok {
		// Should not happen, all operations on dnsMap are synchronized by d.lock
		return false, fmt.Errorf("DNS value not found in dnsMap for domain: %q", dns)
	}

	ips, ttl, retry, err := d.getIPsAndMinTTL(dns)
	if retry {
		// If the DNS lookup has been retried maxRetryCount times, use exponential backoff
		// by doubling the previous TTL. The TTL is capped at defaultMaxTTL.
		if res.retryCount >= maxRetryBeforeBackoff {
			ttl = min(res.ttl*2, defaultMaxTTL)
		} else {
			// Increment the retry count
			res.retryCount++
		}
		// If no valid IPs were found, use the previous IPs as fallback.
		if len(ips) == 0 {
			ips = res.ips
		}
	} else {
		res.retryCount = 0
	}

	changed := false
	if !IsIPsEqual(res.ips, ips) {
		changed = true
	}
	res.ips = ips
	res.ttl = ttl
	res.nextQueryTime = time.Now().Add(res.ttl)
	d.dnsMap[dns] = res
	return changed, err
}

func (d *DNS) getIPsAndMinTTL(domain string) ([]net.IP, time.Duration, bool, error) {
	ips := []net.IP{}
	ttlSet := false
	var minTTL uint32
	var recordTypes []uint16

	if config.IPv4Mode {
		recordTypes = append(recordTypes, dns.TypeA)
	}
	if config.IPv6Mode {
		recordTypes = append(recordTypes, dns.TypeAAAA)
	}

	// Some local resolvers cap TTLs. Keep the first positive answer's addresses,
	// but accept a longer TTL from a later resolver only when its IP set matches;
	// this avoids combining split DNS views while avoiding refreshes based only
	// on the local cap.
	for _, recordType := range recordTypes {
		var familyIPs []net.IP
		var familyTTL uint32
		familyTTLSet := false

		for _, server := range d.nameservers {
			msg := new(dns.Msg)
			dnsOps.SetQuestion(msg, dnsOps.Fqdn(domain), recordType)

			dialServer := server
			if _, _, err := net.SplitHostPort(server); err != nil {
				dialServer = net.JoinHostPort(server, d.port)
			}
			c := new(dns.Client)
			c.Timeout = 5 * time.Second
			in, _, err := dnsOps.Exchange(c, msg, dialServer)
			if err != nil {
				klog.Warningf("Failed to query nameserver: %s with address: %s for domain: %s, err: %v", server, dialServer, domain, err)
				continue
			}
			if in != nil && in.Truncated {
				// if it was fall back on TCP
				c.Net = "tcp"
				// ensure that the old message is overwritten
				msg = new(dns.Msg)
				dnsOps.SetQuestion(msg, dnsOps.Fqdn(domain), recordType)
				in_TCP, _, err := dnsOps.Exchange(c, msg, dialServer)
				if err != nil {
					klog.Warningf("Failed to fall back to TCP to get untruncated DNS results: for domain %s, err: %v", domain, err)
					continue
				}
				in = in_TCP
			}
			if in == nil {
				continue
			}
			if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
				klog.Warningf("Failed to get a valid answer: %v from nameserver: %s for domain: %s", in.Rcode, server, domain)
				continue
			}

			if in.Rcode == dns.RcodeNameError || len(in.Answer) == 0 {
				if !familyTTLSet {
					// A negative response from the first resolver defines this
					// DNS view. Do not use a later resolver's different answer.
					break
				}
				continue
			}

			answerIPs := []net.IP{}
			var answerTTL uint32
			answerTTLSet := false
			for _, answer := range in.Answer {
				if !answerTTLSet || answer.Header().Ttl < answerTTL {
					answerTTL = answer.Header().Ttl
					answerTTLSet = true
				}

				switch record := answer.(type) {
				case *dns.A:
					answerIPs = append(answerIPs, record.A)
				case *dns.AAAA:
					answerIPs = append(answerIPs, record.AAAA)
				}
			}
			if !answerTTLSet {
				continue
			}
			answerIPs = removeDuplicateIPs(answerIPs)

			if !familyTTLSet {
				familyIPs = answerIPs
				familyTTL = answerTTL
				familyTTLSet = true
				if len(familyIPs) == 0 {
					break
				}
				continue
			}

			if IsIPsEqual(familyIPs, answerIPs) && answerTTL > familyTTL {
				familyTTL = answerTTL
			}

		}

		if familyTTLSet {
			ips = append(ips, familyIPs...)
			if !ttlSet || familyTTL < minTTL {
				minTTL = familyTTL
				ttlSet = true
			}
		}
	}

	if !ttlSet || (len(ips) == 0) {
		return nil, defaultMinTTL, true, fmt.Errorf("IPv4 or IPv6 addr not found for domain: %q, nameservers: %v", domain, d.nameservers)
	}

	ips = removeDuplicateIPs(ips)

	ttl, err := time.ParseDuration(fmt.Sprintf("%ds", minTTL))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid TTL value for domain: %q, err: %v", domain, err))
		return ips, defaultMinTTL, true, nil
	}
	if ttl == 0 {
		// If the TTL is 0, return the default minimum TTL. The retry is set to false as this
		// is not an error scenario. TTL being 0 is a valid scenario for some DNS servers
		// and it means that the IP addresses should be refreshed everytime whenever the DNS
		// name is being used. From the point of view of OVN-Kubernetes, the IP addresses are
		// refreshed every defaultMinTTL.
		klog.V(5).Infof("TTL value is 0 for domain: %q, defaulting ttl=%s", domain, defaultMinTTL.String())
		return ips, defaultMinTTL, false, nil
	}

	return ips, ttl, false, nil
}

// GetNextQueryTime returns the earliest refresh time, its DNS name, and
// whether any DNS names are being tracked.
func (d *DNS) GetNextQueryTime() (time.Time, string, bool) {
	d.lock.Lock()
	defer d.lock.Unlock()

	timeSet := false
	var minTime time.Time
	var dns string

	for dnsName, res := range d.dnsMap {
		if !timeSet || res.nextQueryTime.Before(minTime) {
			timeSet = true
			minTime = res.nextQueryTime
			dns = dnsName
		}
	}
	return minTime, dns, timeSet
}

func filterIPServers(servers []string) []string {
	ipServers := []string{}
	for _, server := range servers {

		if ip := net.ParseIP(server); ip != nil {
			if ip.To4() != nil && config.IPv4Mode {
				ipServers = append(ipServers, server)
			} else if ip.To4() == nil && config.IPv6Mode {
				// this is an ipv6 address
				ipServers = append(ipServers, server)
			}
		}
	}

	return ipServers
}

func removeDuplicateIPs(ips []net.IP) []net.IP {
	ipSet := sets.NewString()
	uniqueIPs := []net.IP{}
	for _, ip := range ips {
		if !ipSet.Has(ip.String()) {
			uniqueIPs = append(uniqueIPs, ip)
		}
		ipSet.Insert(ip.String())
	}
	return uniqueIPs
}
