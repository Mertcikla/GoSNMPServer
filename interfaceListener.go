package GoSNMPServer

import (
	"net"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

// Constants for SO_ORIGINAL_DST
const (
	SO_ORIGINAL_DST = 80
	SOL_IP          = 0
)

// sockaddr_in structure for IPv4
type sockaddrIn struct {
	family uint16
	port   uint16
	addr   [4]byte
	zero   [8]uint8
}

type UDPListener struct {
	conn              *net.UDPConn
	logger            ILogger
	lastDestinationIP net.IP // Track the last extracted destination IP
}

type ISnmpServerListener interface {
	SetupLogger(ILogger)
	Address() net.Addr
	NextSnmp() (snmpbytes []byte, replyer IReplyer, err error)
	Shutdown()
}

type IReplyer interface {
	ReplyPDU([]byte) error
	Shutdown()
	GetDestinationIP() net.IP
}

func NewUDPListener(l3proto, address string) (ISnmpServerListener, error) {
	ret := new(UDPListener)
	ret.logger = NewDiscardLogger()
	udpaddr, err := net.ResolveUDPAddr(l3proto, address)
	if err != nil {
		return nil, errors.Wrap(err, "ResolveUDPAddr Error")
	}
	conn, err := net.ListenUDP(l3proto, udpaddr)
	if err != nil {
		return nil, errors.Wrap(err, "UDP Listen Error")
	}

	// Set socket option to receive original destination address
	file, err := conn.File()
	if err != nil {
		return nil, errors.Wrap(err, "get file from conn")
	}
	defer file.Close()
	fd := int(file.Fd())
	// IP_RECVORIGDSTADDR is not defined in syscall for all architectures, so use the value 20
	// See /usr/include/linux/in.h
	const IP_RECVORIGDSTADDR = 20
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_RECVORIGDSTADDR, 1)
	if err != nil {
		// This is expected on non-Linux systems
		ret.logger.Warningf("Could not set IP_RECVORIGDSTADDR socket option: %v. Will not be able to get original destination IP for UDP packets.", err)
	}

	ret.conn = conn
	return ret, nil
}

func (udp *UDPListener) SetupLogger(i ILogger) {
	udp.logger = i
}
func (udp *UDPListener) Address() net.Addr {
	return udp.conn.LocalAddr()
}

func (udp *UDPListener) NextSnmp() ([]byte, IReplyer, error) {
	var msg [4096]byte
	var oob [1024]byte // Out-of-band data for ancillary messages
	if udp.conn == nil {
		return nil, nil, errors.New("Connection Not Listen")
	}

	counts, oobn, _, udpAddr, err := udp.conn.ReadMsgUDP(msg[:], oob[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, "UDP ReadMsgUDP Error")
	}
	udp.logger.Infof("udp request from %v. size=%v", udpAddr, counts)

	// Extract destination IP from ancillary data
	destinationIP := udp.extractDestinationIP(oob[:oobn])
	destinationIP = destinationIP.To4()
	if destinationIP == nil {
		// Fallback for non-linux or if ancillary data is not available
		destinationIP = udp.conn.LocalAddr().(*net.UDPAddr).IP
		udp.logger.Debugf("Could not get original destination from ancillary data, falling back to local address: %s", destinationIP)
	}
	return msg[:counts], &UDPReplyer{
		target:        udpAddr,
		conn:          udp.conn,
		destinationIP: destinationIP,
	}, nil
}

func (udp *UDPListener) extractDestinationIP(oob []byte) net.IP {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		udp.logger.Errorf("Error parsing socket control message: %v", err)
		return nil
	}

	for _, msg := range msgs {
		// IP_RECVORIGDSTADDR is not defined in syscall for all architectures, so use the value 20
		const IP_RECVORIGDSTADDR = 20
		if msg.Header.Level == syscall.IPPROTO_IP && msg.Header.Type == IP_RECVORIGDSTADDR {
			// The data is a sockaddr_in structure
			if len(msg.Data) >= int(unsafe.Sizeof(sockaddrIn{})) {
				addr := (*sockaddrIn)(unsafe.Pointer(&msg.Data[0]))
				ip := net.IPv4(addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3])
				udp.logger.Debugf("Extracted original destination IP: %v from ancillary data", ip)
				return ip
			}
		}
	}

	udp.logger.Debugf("Original destination IP not found in ancillary data")
	return nil
}

func (udp *UDPListener) Shutdown() {
	if udp.conn != nil {
		udp.conn.Close()
		udp.conn = nil
	}
}

type UDPReplyer struct {
	target        *net.UDPAddr
	conn          *net.UDPConn
	destinationIP net.IP
}

func (r *UDPReplyer) ReplyPDU(i []byte) error {
	conn := r.conn
	_, err := conn.WriteToUDP(i, r.target)
	if err != nil {
		return errors.Wrap(err, "WriteToUDP")
	}
	return nil
}

func (r *UDPReplyer) Shutdown() {}

func (r *UDPReplyer) GetDestinationIP() net.IP {
	return r.destinationIP
}
