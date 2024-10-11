package device

func (device *Device) CountPeersWithValidSessions() float64 {
	var rv float64 = 0
	device.peers.Lock()
	for _, peer := range device.peers.keyMap {
		if peer.isRunning.Load() {
			if peer.HasValidKeypair() {
				rv += 1
			}
		}
	}
	device.peers.Unlock()
	return rv
}

func (device *Device) CountPeers() float64 {
	return float64(len(device.peers.keyMap))
}
