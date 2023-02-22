# ********************************************************************************
# Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
# You may use this software and any derivatives exclusively with
# Microchip products.
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS".
# NO WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,
# INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,
# AND FITNESS FOR A PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP
# PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
# IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
# INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
# WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
# BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.
# TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL
# CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF
# FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
# MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE
# OF THESE TERMS.
# ********************************************************************************/

# -------------------------------------- PLDM COMMANDS RELATED STRUCTURES --------------------------------------

class QueryId:
    def __init__(self):
        self.completion_code = 0
        self.device_identifiers_length = 0
        self.descriptor_count = 0
        self.descriptor = []


size_mem_Q_id = [
    0x1,
    0x4,
    0x1,
    0x200
]


class GetFwPm:
    def __init__(self):
        self.completion_code = 0
        self.capabilities_during_update = 0
        self.component_count = 0
        self.active_comp_image_set_version_string_type = 0
        self.active_comp_image_set_version_string_length = 0
        self.pending_comp_image_set_version_string_type = 0
        self.pending_comp_image_set_version_string_length = 0
        self.active_comp_image_set_version_string = 0
        self.pending_comp_image_set_version_string = 0


size_mem_GetFwPm = [
    0x1,
    0x4,
    0x2,
    0x1,
    0x1,
    0x1,
    0x1,
    -1,
    -1
]
# q_id = QueryId()


class GetFwPm_comp_pm_table:
    def __init__(self):
        self.comp_classification = 0
        self.comp_identifier = 0
        self.comp_classification_index = 0
        self.active_comp_comparison_stamp = 0
        self.active_comp_version_string_type = 0
        self.active_comp_version_string_length = 0
        self.active_comp_release_date = 0
        self.pending_comp_comparison_stamp = 0
        self.pending_comp_version_string_type = 0
        self.pending_comp_version_string_length = 0
        self.pending_comp_release_date = 0
        self.comp_activation_methods = 0
        self.cap_during_update = 0
        self.active_comp_version_string = 0
        self.pending_comp_version_string = 0


size_mem_GetFwPm_cpt = [
    0x2,
    0x2,
    0x1,
    0x4,
    0x1,
    0x1,
    0x8,
    0x4,
    0x1,
    0x1,
    0x8,
    0x2,
    0x4,
    -1,
    -1
]
# ------------------------------------- PLDM COMMANDS RELATED STRUCTURES END --------------------------------------

# ------------------------------------- PLDM HEADER RELATED STRUCTURES ---------------------------------


class fw_pkg_hdr:
    def __init__(self):
        self.PackageHeaderIdentifier = 0
        self.PackageHeaderFormatRevision = 0
        self.PackageHeaderSize = 0
        self.PackageReleaseDateTime = 0
        self.ComponentBitmapBitLength = 0
        self.PackageVersionStringType = 0
        self.PackageVersionStringLength = 0
        self.PackageVersionString = 0


size_fw_pkg_hdr = [
    16,  # PackageHeaderIdentifier
    1,   # PackageHeaderFormatRevision
    2,   # PackageHeaderSize
    13,  # PackageReleaseDateTime
    2,   # ComponentBitmapBitLength
    1,   # PackageVersionStringType
    1,   # PackageVersionStringLength
    -1,  # PackageVersionString
]


class Firmware_Device_Identification_Area:
    def __init__(self):
        self.DeviceIDRecordCount = 0
        self.RecordLength = 0
        self.DescriptorCount = 0
        self.DeviceUpdateOptionFlags = 0
        self.ComponentImageSetVersionStringType = 0
        self.ComponentImageSetVersionStringLength = 0
        self.FirmwareDevicePackageDataLength = 0
        self.ApplicableComponents = 0  # todo
        self.ComponentImageSetVersionString = 0


size_fw_dev_id = [
    1,   # DeviceIDRecordCount
    2,   # RecordLength
    1,   # DescriptorCount
    4,   # DeviceUpdateOptionFlags
    1,   # ComponentImageSetVersionStringType
    1,   # ComponentImageSetVersionStringLength
    2,   # FirmwareDevicePackageDataLength
    -1,   # ApplicableComponents # todo
    -1,  # ComponentImageSetVersionString
]


class Firmware_Device_Identification_Descriptor:
    def __init__(self):
        self.InitialDescriptorType = 0
        self.InitialDescriptorLength = 0
        self.InitialDescriptorData = 0


size_fw_dev_id_desc = [
    2,   # InitialDescriptorType
    2,   # InitialDescriptorLength
    -1,  # InitialDescriptorData
]


class Component_Image_Count:
    def __init__(self):
        self.ComponentImageCount = 0


size_ComponentImageCount = [
    2,  # ComponentImageCount
]


class Component_Image_Information:
    def __init__(self):
        self.ComponentClassification = 0
        self.ComponentIdentifier = 0
        self.ComponentComparisonStamp = 0
        self.ComponentOptions = 0
        self.RequestedComponentActivationMethod = 0
        self.ComponentLocationOffset = 0
        self.ComponentSize = 0
        self.ComponentVersionStringType = 0
        self.ComponentVersionStringLength = 0
        self.ComponentVersionString = 0


size_Component_Image_Information = [
    2,  # ComponentClassification
    2,  # ComponentIdentifier
    4,  # ComponentComparisonStamp
    2,  # ComponentOptions
    2,  # RequestedComponentActivationMethod
    4,  # ComponentLocationOffset
    4,  # ComponentSize
    1,  # ComponentVersionStringType
    1,  # ComponentVersionStringLength
    -1  # ComponentVersionString
]

# ------------------------------------- PLDM HEADER RELATED STRUCTURES END ---------------------------------
