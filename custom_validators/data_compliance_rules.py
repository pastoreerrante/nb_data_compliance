import re
from nautobot.apps.models import DataComplianceRule, ComplianceError
from nautobot.apps.models import CustomValidator, CustomValidatorIterator

class DeviceDataComplianceRules(DataComplianceRule):
    model = "dcim.device"
    enforce = False

    # Checks if a device name contains any special characters other than a dash (-), underscore (_), or period (.) using regex
    def audit_device_name_chars(self):
        if not re.match("^[a-zA-Z0-9\-_.]+$", self.context["object"].name):
            raise ComplianceError({"name": "Device name contains unallowed special characters."})

    def audit(self):
        messages = {}
        for fn in [self.audit_device_name_chars]:
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)

custom_validators = list(CustomValidatorIterator()) + [DeviceDataComplianceRules]