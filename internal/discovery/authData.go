package discovery

import (
	"errors"
	"fmt"
	"github.com/grandcat/zeroconf"
	"k8s.io/klog"
	"net"
	"sync"
	"time"
)

type AuthData struct {
	address string
	port    int
}

func (authData *AuthData) Get(discovery *DiscoveryCtrl, entry *zeroconf.ServiceEntry) error {
	if discovery.isForeign(entry.AddrIPv4) {
		return authData.Decode(entry, discovery.dialTcpTimeout)
	}
	return nil
}

func (authData *AuthData) IsComplete() bool {
	return authData.address != "" && authData.port > 0
}

func (authData *AuthData) GetUrl() string {
	return fmt.Sprintf("https://%v:%v", authData.address, authData.port)
}

func (authData *AuthData) Decode(entry *zeroconf.ServiceEntry, timeout time.Duration) error {
	authData.port = entry.Port

	ip, err := getReachable(entry.AddrIPv4, entry.Port, timeout)
	if err != nil {
		ip, err = getReachable(entry.AddrIPv6, entry.Port, timeout)
	}
	if err != nil {
		klog.Errorf("%v %v %v", err, entry.AddrIPv4, entry.Port)
		return err
	}

	authData.address = ip.String()
	return nil
}

func getReachable(ips []net.IP, port int, timeout time.Duration) (*net.IP, error) {
	resChan := make(chan int, len(ips))
	defer close(resChan)
	wg := sync.WaitGroup{}
	wg.Add(len(ips))

	// search in an async way for all reachable ips
	for i, ip := range ips {
		go func(ip net.IP, port int, index int, ch chan int) {
			if !ip.IsLoopback() && !ip.IsMulticast() && isReachable(ip.String(), port, timeout) {
				ch <- index
			}
			wg.Done()
		}(ip, port, i, resChan)
	}
	wg.Wait()

	// if someone is reachable return its index
	select {
	case i := <-resChan:
		return &ips[i], nil
	default:
		return nil, errors.New("server not reachable")
	}
}

func isReachable(address string, port int, timeout time.Duration) bool {
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", address, port), timeout)
	klog.V(4).Infof("%s:%d %v", address, port, err)
	return err == nil
}
