# forward-broadcasts

This daemon can be used alongside `parprouted`, `dhcp-helper` *et al* to bridge between
wired and wireless networks.  It will forward IP broadcast frames from one interface
to another.

## Usage

`forward-broadcasts [-d] <listen if> <output if>`

e.g.

`forward-broadcasts wlan0 eth0`

will retransmit broadcasts frames seen on wlan0 to eth0.

## Author

Ian Chard <ian@chard.org>
