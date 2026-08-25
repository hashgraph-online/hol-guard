from device_base import DeviceBase
from device_outbox import DeviceOutboxMixin
from device_policy import DevicePolicyMixin
from device_remediation import DeviceRemediationMixin


class Device(DeviceRemediationMixin, DevicePolicyMixin, DeviceOutboxMixin, DeviceBase):
    """Complete independently keyed HOL Guard MDM endpoint."""

    pass
