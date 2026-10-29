from pydantic import BaseModel, Field, ConfigDict, field_validator
from ipaddress import ip_address
from typing import Literal

EventType = Literal["failed_login", "successful_login", "sql_injection", "port_scan", "malware_indicator", "other"]

class AlertIn(BaseModel):
    model_config = ConfigDict(extra='forbid',json_schema_extra={'examples':[{
        'source_ip':'8.8.8.8','event_type':'failed_login','target':'demo-login',
        'details':'Controlled simulation alert','severity':'high'}]})
    source_ip: str = Field(min_length=3, max_length=64)
    event_type: EventType
    target: str = Field(min_length=1, max_length=200)
    details: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"

    @field_validator('source_ip')
    @classmethod
    def address(cls,value):
        return str(ip_address(value))

class SimulateIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scenario: Literal["brute_force", "sql_injection", "normal_login"] = "brute_force"
    source_ip: str = "198.51.100.23"
    target: str = "demo-login"

    @field_validator('source_ip')
    @classmethod
    def address(cls,value):
        return str(ip_address(value))
