# Usage notes

smoltcp expects a packet path as below, just like any standard networking path.

Rx Pkt--phy[l2 pkts]-->iface[l3 pkts]-->Rx tcp/udp socket[l4 data]-->application

application-->[l4 data]smoltcp tcp/udp socket-->[l3 pkts]iface-->[l2 pkts]phy--> Tx Pkt

There are some ready to use phy modules available (see src/phy) like ethernet raw socket,
tun/tap interfaces, file descriptors, generic IP packet queues etc.. 

## smoltcp as a server

### TCP

In the server.rs example, this is the general pattern followed

  create-unix-tap-interface
  phy = Fd (file descriptor of tap)
  iface = create-iface(phy, <ip address of iface>, <mac address of phy>);
  socket1 = create-tcp-socket(rx-buffer, tx-buffer)
  socket.listen(6969) // the port on which we expect clients to connect to
  socket_set = create-set(socket1, <more sockets if any ..>) // socket set will be explained down below

  loop {
    // The poll API does the below
    // 1. It calls the Rx routines of the phy, gets a new packet from the phy, and gives it to the 
    //    interface, interface makes it into an ip packet, and if the destination IP is the interface
    //    IP, then it tries to match the destination protocol & port against one of the sockets in 
    //    the socket_set. In our example, lets say packet was to tcp port 6969, so it matches socket1,
    //    and associates the client info ("endpoint" info) with socket1 - ie a new client trying to
    //    connect to the iface IP + tcp 6969 will NOT be able to use socket1, we will have to have 
    //    added an extra socket say socket2 with the same port 6969 if a new client wants to connect
    //
    // 2. The poll routine runs the packet through the TCP (or udp if socket is udp) state machine, 
    //    if it was a SYN packet, the tcp state machine will generate a SYN-ACK for transmit and it
    //    will sit in the tx-buffer of the socket. If it was a data packet, the data is copied into 
    //    the socket's Rx buffer and the next socket1.recv() call will get the data from that buffer
    //
    //    NOTE: If the socket's rx buffer is full, the poll routine will simply discard the packet.
    //    In case of tcp, that will mean the sender will eventually retry, in case of udp thats a 
    //    packet loss
    //
    // 3. The poll routine checks if the socket's Tx buffer has anything to be transmitted - either 
    //    control packets like a SYN-ACK or a ACK or FIN/RST etc.., or data packets written by the
    //    application by calling socket1.send_slice(). If there is tx data, the poll routine will
    //    take as much data out as possible. Note that if the tx-buffer was full when the application
    //    tried to do a socket1.send_slice(), the send_slice() will return a value indicating buffer
    //    full and its upto the application to retry again later
    iface.poll(socket_set) 

    // After iface poll, we "may" have Rx application data in zero or more sockets in the socket-set,
    // so call .recv() on each of the sockets - there is no indication as of today as to which socket
    // might have data after the poll, so need to do recv() on all of them.

    // After the iface poll, zero or more sockets "may" have Tx buffer space available for applications
    // to try and write more data, so this is a good point to let applications know to retry writing
    // data (calling send() or send_slice() on the socket)
  }

NOTE1: As explained in point 1 above, a new socket connection is "bound" to a yet-unused socket in
the socket set. So if we are expecting like a hundred connections simultaneously to port 6969, we
need to pre-create hundred socket structures all initialized with .listen(6969)

NOTE2: The rx buffer size will typically determine the maximum tcp window size advertised to the
other end. The rx buffer is pre-allocated and will NOT grow.

#### may_send/can_send and may_recv/can_recv

may_send() checks to see if the socket is handshake complete, and we (application) have not yet closed 
the transmit half of the connection. can_send() checks if there is any room in the tx buffer to queue
up more packets to send - this does not say "how many" bytes can be queued up, it will just say if there
it at least one byte that can be queued up. can_send() checks may_send() first and then checks the
buffer details

may_recv() checks if the handshake is complete and the other end has not closed the connection, and if
so we can potentially receive more data. The can_recv() checks if there is any data in the rx buffer,
if the rx buffer is empty then there is nothing to receive. Again its just a zero or non-zero indication
and does not tell the exact number of bytes etc.. can_recv() checks may_recv() first and then the
buffer details.

So if you want to know the tcp states to maybe signal the application to close / terminate etc..,
may_send()/may_recv() are good indicators. If you want to know if more data can be sent/received,
can_send()/can_recv() are good indicators

### UDP

The general theory of operation mentioned about TCP above also applies to UDP. A few things to keep
in mind for UDP which are different from TCP

1. TCP needs one socket per client trying to connect to us, as explained earlier. But for UDP, since
   its a connection-less protocol, the udp packets in the rx / tx buffers are also storing the 
   "meta data" about the remove client's IP/port (src-ip/src-port). So we just need a single socket
   for say port 6969 udp, and with that single socket in the socket_set used with poll(), we can let
   many remote clients connect to it. The only drawback is that for udp, when transmitting the data
   using the send_slice() api, we also need to specify the "endpoint" (ie the client) to which we
   are trasmitting the data. In typical socket libraries there would be one socket per client, just
   like the tcp example, but for udp there is one socket for the server ip / server port and all
   clients just multiplex over that

2. The Rx buffer for UDP is basically a ring buffer .. But if we call send_slice(), smoltcp will
   try to find a 'contiguous' are of the ring to enqueue the entire data passed in send_slice().
   Remember this is UDP and we cant sent partial data, so we need to send all or nothing, but the
   ring buffer contiguity enforcement means that if we allocate say 1500 bytes of buffer and then
   send 200 bytes of data, after the 200 bytes is transmitted the ring buffer advanced by 200 bytes,
   and now the only contiguous buffer available is 1300 bytes. So the next send_slice() call to 
   send 1500 bytes will NEVER succeed how many ever times we retry. So for UDP, make sure we 
   allocate two times the size of the largest data packet we plan to send, so we always have one
   max-data-packet worth of contiguous buffer always available.


### smoltcp as a proxy 

In the above description, the iface was always created with one particular ip address - usually
the ip address on which the server expects to receive packets. But what if we want to run smoltcp
as a proxy, where we want to intercept ALL packets - not just packets destined to our IP, but packets
destined to ANY ip. Its pretty straight forward, the principles above still apply, naturally we
need an iface for every ip address we expect. The general code flow will be as below

The proxy application:

1. Get an Rx IP packet, figure out the five tuple (src-ip, src-port, dest-ip, dest-port, protocol)
   from the packet

2. See if the five tuple has been seen before, if not create an iface with dest-ip as the dest-ip
   of the packet, create a socket with the (dest-port, protocol) and do .listen(dest-port) for 
   tcp or .bind(dest-port) for udp. And save this (iface, socket) info such that the next time
   we see a packet with the same tuple, we can lookup this (iface, socket)

3. Create a socket-set with just one socket, the one created above, lets call it singleton-set
   And then do iface.poll(singleton-set) - this will try to pull in Rx packets into the socket
   and generate tx packets out of the socket etc.. as explained before

4. For any future ip packet, lookup the tuple, find the iface created & associated in step 2,
   and then do iface.poll() using that iface

So basically we are just creating one iface + socket combination for every tcp/udp five tuple.
We noted earlier than udp sockets can be one for many endpoints, those features can be used 
with modifications in the steps above, but the steps above just clarify in simple terms how
to make a proxy work.

Although one thing we ignored here is the matter of "phy" - in all the examples before, the
phy was the one which was reading / writing packets from a real/virtual ethernet device. But
in our case, as seen in step 1, the control over the read/write from the device is with the
proxy application and we dont want to hand over that responsibility to smoltcp. 

So for that reason we can create a "packet queue" device adhering to the Device trait 
(src/phy/loopback.rs is a good example), which can be used as the phy in this example.
The new phy will have nothing but a simple rx and tx queue. So in step1, whatever packet is 
received is put into the rx queue. And the iface.poll() will read from that queue - the packetq
APIs ensure that when iface asks for an Rx packet, its provided from the rx queue. Similarly 
when iface poller wants to send a packet, its simply enqueued into the tx queue, and the proxy
application can choose to send that packet in whatever way it deems fit - as an ethernet or 
tunneled over some VPN etc.. etc..


