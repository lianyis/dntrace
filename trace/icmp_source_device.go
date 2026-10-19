package trace

import "github.com/lianyis/dntrace/trace/internal"

func applyICMPSourceDevice(spec *internal.ICMPSpec, osType int, sourceDevice string) {
	if spec == nil || sourceDevice == "" || osType == osTypeWindows || !supportsSourceDeviceBinding(currentGOOS) {
		return
	}
	spec.SourceDevice = sourceDevice
}
