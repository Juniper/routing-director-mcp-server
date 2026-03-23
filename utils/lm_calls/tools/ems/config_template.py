from pydantic import BaseModel, Field
from typing import Optional, Literal

class ConfigTemplate(BaseModel):
    """Configuration template structure for Routing Director"""

    name: str = Field(
        ...,
        description="Human-readable name for the template",
        example="Set Interface Descriptions"
    )

    description: Optional[str] = Field(
        None,
        description="Detailed description of what the template does",
        example="Set description on multiple interfaces"
    )

    type: Literal["netconf-edit", "cli", "netconf-get", "rpc"] = Field(
        ...,
        description="Type of configuration template",
        example="netconf-edit"
    )

    device_vendor: Literal["Juniper", "Cisco", "Arista", "Nokia", "Huawei"] = Field(
        ...,
        description="Target device vendor",
        example="Juniper"
    )

    device_family: str = Field(
        ...,
        description="Target device family or model series",
        example="Juniper-Any or ACX, MX, PTX, QFX, EX, etc."
    )

    template: str = Field(
        ...,
        description="The actual template content (NETCONF XML, CLI commands, etc.) with Jinja2 templating syntax. Use \\n for line breaks. For CLI commands make sure it starts with configure and ends with commit.",
        example="<edit-config>\\n<target><candidate /></target>\\n<default-operation>merge</default-operation>\\n<config><configuration><interfaces>\\n{% for interface in interfaces %}<interface>\\n<name>{{ interface.name }}</name><description>{{ interface.description }}</description>\\n</interface>{% endfor %}\\n</interfaces></configuration></config>\\n</edit-config>"
    )
