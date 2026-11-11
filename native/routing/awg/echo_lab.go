//go:build stability_trace

package awg

import (
 "bytes"
 "context"
 "encoding/binary"
 "time"
 "gvisor.dev/gvisor/pkg/tcpip"
 "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
 "gvisor.dev/gvisor/pkg/waiter"
)

// LabEcho is header/payload observation for disposable fixture builds.
func(s *FlowStack) LabEcho(ctx context.Context,size int) bool {
 if size<28||size>1280{return false}
 var q waiter.Queue
 ep,err:=s.stack.NewEndpoint(icmp.ProtocolNumber4,ipv4.ProtocolNumber,&q);if err!=nil{return false};defer ep.Close()
 if ep.Connect(tcpip.FullAddress{NIC:1,Addr:tcpip.AddrFrom4([4]byte{10,77,0,1})})!=nil{return false}
 b:=make([]byte,size-20);b[0]=8;binary.BigEndian.PutUint16(b[6:],1)
 for i:=8;i<len(b);i++{b[i]=byte(i*31)}
 if _,e:=ep.Write(bytes.NewReader(b),tcpip.WriteOptions{});e!=nil{return false}
 for {
 var out bytes.Buffer
 if _,e:=ep.Read(&out,tcpip.ReadOptions{});e==nil{return len(out.Bytes())>=8 && out.Bytes()[0]==0 && bytes.Equal(out.Bytes()[8:],b[8:])}
 select{case <-ctx.Done():return false;case <-time.After(10*time.Millisecond):}
 }
}
