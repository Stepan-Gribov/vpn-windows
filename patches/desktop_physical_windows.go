package tun
// SetDesktopPhysicalInterface follows the chosen physical uplink after a network
// change without restarting the user's packet stack or changing split lists.
func SetDesktopPhysicalInterface(name string) { if updater != nil { updater.Lock();updater.fixedName=name;updater.Unlock();updater.Update() } }
