import re
from nautobot.apps.models import DataComplianceRule, ComplianceError


class DesiredClassName(DataComplianceRule):
    model = "desired.model"  # Ex: 'dcim.device'
    enforce = False  # True/False enforce flag

    def audit_desired_name_one(self):
        # Your logic to determine if this function has succeeded or failed
        if self.context["object"].desired_attribute == "undesired_value":
            raise ComplianceError(
                {"desired_attribute": "Desired message why it's invalid."}
            )

    def audit_desired_name_two(self):
        # Your logic to determine if this function has succeeded or failed
        if "undesired_value" in self.context["object"].desired_attribute:
            raise ComplianceError(
                {"desired_attribute": "Desired message why it's invalid."}
            )

    def audit(self):
        messages = {}
        for fn in [
            self.audit_desired_name_one,
            self.audit_desired_name_two,
        ]:  # Add audit functions here
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)
