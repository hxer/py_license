from typing import Dict, Optional
from datetime import datetime
from pydantic import BaseModel


class SignData(BaseModel):
    product_name: str
    product_version: str
    license_generation_time: datetime
    license_begin_time: datetime
    license_end_time: datetime
    customer_name: str
    authorization_method: str   # 可选： feature、nodes
    authorization_details: Optional[Dict] = None
    remarks: Optional[str] = None
    extension_field: Optional[Dict] = None
