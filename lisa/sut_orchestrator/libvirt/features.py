from dataclasses import dataclass, field
from typing import Any, Type, cast

from dataclasses_json import dataclass_json

from lisa import features, schema, search_space
from lisa.environment import Environment
from lisa.features.security_profile import SecurityProfileType
from lisa.sut_orchestrator.libvirt.context import get_node_context
from lisa.util import field_metadata
from lisa.node import Node

@dataclass_json()
@dataclass()
class AzureFeatureMixin:
    def _initialize_information(self, node: Node) -> None:
        node_context = get_node_context(node)
        self._vm_name = node_context.vm_name

class SecurityProfileSettings(features.SecurityProfileSettings):
    disk_encryption_set_id: str = field(
        default="",
        metadata=field_metadata(
            required=False,
        ),
    )

    def __hash__(self) -> int:
        return hash(self._get_key())

    def _get_key(self) -> str:
        return (
            f"{self.type}/{self.security_profile}/"
            f"{self.encrypt_disk}/{self.disk_encryption_set_id}"
        )

    def _call_requirement_method(
        self, method: search_space.RequirementMethod, capability: Any
    ) -> Any:
        super_value: SecurityProfileSettings = super()._call_requirement_method(
            method, capability
        )
        value = SecurityProfileSettings()
        value.security_profile = super_value.security_profile
        value.encrypt_disk = super_value.encrypt_disk
        if self.disk_encryption_set_id:
            value.disk_encryption_set_id = self.disk_encryption_set_id
        else:
            value.disk_encryption_set_id = capability.disk_encryption_set_id

        return value

class SecurityProfile(AzureFeatureMixin, features.SecurityProfile):
    _security_profile_mapping = {
        SecurityProfileType.Standard: "",
        SecurityProfileType.CVM: "ConfidentialVM",
    }

    def _initialize(self, *args: Any, **kwargs: Any) -> None:
        super()._initialize(*args, **kwargs)
        self._initialize_information(self._node)

    @classmethod
    def settings_type(cls) -> Type[schema.FeatureSettings]:
        return SecurityProfileSettings
    
    def on_before_deployment(cls, *args: Any, **kwargs: Any) -> None:
        environment = cast(Environment, kwargs.get("environment"))
        security_profile = [kwargs.get("settings")]

        for node in environment.nodes._list:
            assert node.capability.features
            if security_profile:
                settings = security_profile[0]
                assert isinstance(settings, SecurityProfileSettings)
                assert isinstance(settings.security_profile, SecurityProfileType)
                node_context = get_node_context(node)
                node_context.guest_vm_type = cls._security_profile_mapping[
                    settings.security_profile
                ]