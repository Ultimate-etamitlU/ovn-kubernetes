// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"fmt"
	"net"
	"testing"

	"github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

// newMinimalController creates a Controller with only the fields required to
// exercise the UDN-enabled service route/policy methods. It avoids the watch
// factory so the test does not require a live API server for NAD informer sync.
func newMinimalController(t *testing.T, dbSetup libovsdbtest.TestSetup, netInfo util.NetInfo) (*Controller, func()) {
	t.Helper()
	nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(dbSetup, nil)
	if err != nil {
		t.Fatalf("failed to create NB harness: %v", err)
	}
	c := &Controller{
		nbClient: nbClient,
		netInfo:  netInfo,
	}
	return c, func() { cleanup.Cleanup() }
}

// TestConfigureUDNEnabledServiceRoute verifies the dispatch and DB writes for
// UDN-enabled default services (e.g. kube-dns) on primary UDN networks.
//
// Layer3 and Layer2-with-transit-router topologies must produce per-node LR
// policies on the UDN cluster router (priority=400, inport+dst match).
// Layer2 without a transit router must produce static routes on per-node GW
// routers (the unchanged pre-fix behaviour).
func TestConfigureUDNEnabledServiceRoute(t *testing.T) {
	const (
		ns          = "kube-system"
		serviceName = "kube-dns"
		clusterIP   = "10.96.0.10"
		mgmtIPNodeA = "10.244.0.1"
		mgmtIPNodeB = "10.244.1.1"
	)

	oldIPv4 := config.IPv4Mode
	oldIPv6 := config.IPv6Mode
	oldUDN := config.Default.UDNAllowedDefaultServices
	oldL2Transit := config.Layer2UsesTransitRouter
	t.Cleanup(func() {
		config.IPv4Mode = oldIPv4
		config.IPv6Mode = oldIPv6
		config.Default.UDNAllowedDefaultServices = oldUDN
		config.Layer2UsesTransitRouter = oldL2Transit
	})
	config.IPv4Mode = true
	config.IPv6Mode = false
	config.Default.UDNAllowedDefaultServices = []string{fmt.Sprintf("%s/%s", ns, serviceName)}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: clusterIP,
		},
	}

	t.Run("Layer3 UDN creates per-node LR policies on cluster router", func(t *testing.T) {
		g := gomega.NewWithT(t)

		l3UDN, err := getSampleUDNNetInfo(ns, types.Layer3Topology)
		g.Expect(err).NotTo(gomega.HaveOccurred())

		routerName := l3UDN.GetNetworkScopedClusterRouterName()
		controller, cleanup := newMinimalController(t, libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalRouter{UUID: routerName, Name: routerName},
			},
		}, l3UDN)
		defer cleanup()

		controller.nodeInfos = []nodeInfo{
			{name: nodeA, mgmtIPs: []net.IP{net.ParseIP(mgmtIPNodeA)}, zone: types.OvnDefaultZone},
			{name: nodeB, mgmtIPs: []net.IP{net.ParseIP(mgmtIPNodeB)}, zone: types.OvnDefaultZone},
		}

		g.Expect(controller.configureUDNEnabledServiceRoute(service)).To(gomega.Succeed())

		extIDs := map[string]string{
			types.NetworkExternalID:           l3UDN.GetNetworkName(),
			types.TopologyExternalID:          l3UDN.TopologyType(),
			types.UDNEnabledServiceExternalID: fmt.Sprintf("%s/%s", ns, serviceName),
		}
		policyNodeA := &nbdb.LogicalRouterPolicy{
			UUID:        "policy-node-a",
			Priority:    types.UDNEnabledServicePolicyPriority,
			Match:       fmt.Sprintf("inport == %q && ip4.dst == %s", l3UDN.GetNetworkScopedRouterToSwitchPortName(nodeA), clusterIP),
			Action:      nbdb.LogicalRouterPolicyActionReroute,
			Nexthops:    []string{mgmtIPNodeA},
			ExternalIDs: extIDs,
		}
		policyNodeB := &nbdb.LogicalRouterPolicy{
			UUID:        "policy-node-b",
			Priority:    types.UDNEnabledServicePolicyPriority,
			Match:       fmt.Sprintf("inport == %q && ip4.dst == %s", l3UDN.GetNetworkScopedRouterToSwitchPortName(nodeB), clusterIP),
			Action:      nbdb.LogicalRouterPolicyActionReroute,
			Nexthops:    []string{mgmtIPNodeB},
			ExternalIDs: extIDs,
		}
		expectedRouter := &nbdb.LogicalRouter{
			UUID:     routerName,
			Name:     routerName,
			Policies: []string{"policy-node-a", "policy-node-b"},
		}

		g.Expect(controller.nbClient).To(libovsdbtest.HaveData([]libovsdbtest.TestData{
			policyNodeA,
			policyNodeB,
			expectedRouter,
		}))
	})

	t.Run("Layer3 UDN cleanup removes LR policies", func(t *testing.T) {
		g := gomega.NewWithT(t)

		l3UDN, err := getSampleUDNNetInfo(ns, types.Layer3Topology)
		g.Expect(err).NotTo(gomega.HaveOccurred())

		routerName := l3UDN.GetNetworkScopedClusterRouterName()
		serviceKey := fmt.Sprintf("%s/%s", ns, serviceName)
		extIDs := map[string]string{
			types.NetworkExternalID:           l3UDN.GetNetworkName(),
			types.TopologyExternalID:          l3UDN.TopologyType(),
			types.UDNEnabledServiceExternalID: serviceKey,
		}
		existingPolicyA := &nbdb.LogicalRouterPolicy{
			UUID:        "policy-node-a",
			Priority:    types.UDNEnabledServicePolicyPriority,
			Match:       fmt.Sprintf("inport == %q && ip4.dst == %s", l3UDN.GetNetworkScopedRouterToSwitchPortName(nodeA), clusterIP),
			Action:      nbdb.LogicalRouterPolicyActionReroute,
			Nexthops:    []string{mgmtIPNodeA},
			ExternalIDs: extIDs,
		}
		existingPolicyB := &nbdb.LogicalRouterPolicy{
			UUID:        "policy-node-b",
			Priority:    types.UDNEnabledServicePolicyPriority,
			Match:       fmt.Sprintf("inport == %q && ip4.dst == %s", l3UDN.GetNetworkScopedRouterToSwitchPortName(nodeB), clusterIP),
			Action:      nbdb.LogicalRouterPolicyActionReroute,
			Nexthops:    []string{mgmtIPNodeB},
			ExternalIDs: extIDs,
		}

		controller, cleanup := newMinimalController(t, libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				existingPolicyA,
				existingPolicyB,
				&nbdb.LogicalRouter{
					UUID:     routerName,
					Name:     routerName,
					Policies: []string{"policy-node-a", "policy-node-b"},
				},
			},
		}, l3UDN)
		defer cleanup()

		controller.nodeInfos = []nodeInfo{
			{name: nodeA, mgmtIPs: []net.IP{net.ParseIP(mgmtIPNodeA)}, zone: types.OvnDefaultZone},
			{name: nodeB, mgmtIPs: []net.IP{net.ParseIP(mgmtIPNodeB)}, zone: types.OvnDefaultZone},
		}

		g.Expect(controller.cleanupUDNEnabledServiceRoute(serviceKey)).To(gomega.Succeed())

		// After cleanup: router persists, policies are deleted.
		g.Expect(controller.nbClient).To(libovsdbtest.HaveData([]libovsdbtest.TestData{
			&nbdb.LogicalRouter{UUID: routerName, Name: routerName},
		}))
	})

	t.Run("Layer2 without transit router uses static routes on per-node GW routers", func(t *testing.T) {
		g := gomega.NewWithT(t)

		config.Layer2UsesTransitRouter = false

		l2UDN, err := getSampleUDNNetInfo(ns, types.Layer2Topology)
		g.Expect(err).NotTo(gomega.HaveOccurred())

		gwRouterNameA := l2UDN.GetNetworkScopedGWRouterName(nodeA)
		controller, cleanup := newMinimalController(t, libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalRouter{UUID: gwRouterNameA, Name: gwRouterNameA},
			},
		}, l2UDN)
		defer cleanup()

		controller.nodeInfos = []nodeInfo{
			{
				name:              nodeA,
				mgmtIPs:           []net.IP{net.ParseIP(mgmtIPNodeA)},
				zone:              types.OvnDefaultZone,
				gatewayRouterName: gwRouterNameA,
			},
		}

		g.Expect(controller.configureUDNEnabledServiceRoute(service)).To(gomega.Succeed())

		extIDs := map[string]string{
			types.NetworkExternalID:           l2UDN.GetNetworkName(),
			types.TopologyExternalID:          l2UDN.TopologyType(),
			types.UDNEnabledServiceExternalID: fmt.Sprintf("%s/%s", ns, serviceName),
		}
		expectedRoute := &nbdb.LogicalRouterStaticRoute{
			UUID:        "static-route-node-a",
			Policy:      &nbdb.LogicalRouterStaticRoutePolicyDstIP,
			IPPrefix:    clusterIP,
			Nexthop:     mgmtIPNodeA,
			ExternalIDs: extIDs,
		}
		expectedRouter := &nbdb.LogicalRouter{
			UUID:         gwRouterNameA,
			Name:         gwRouterNameA,
			StaticRoutes: []string{"static-route-node-a"},
		}

		g.Expect(controller.nbClient).To(libovsdbtest.HaveData([]libovsdbtest.TestData{
			expectedRoute,
			expectedRouter,
		}))
	})
}
