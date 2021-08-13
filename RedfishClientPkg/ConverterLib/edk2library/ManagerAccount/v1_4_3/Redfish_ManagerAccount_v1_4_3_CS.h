//
// Auto-generated file by Redfish Schema C Structure Generator.
// https://github.com/DMTF/Redfish-Schema-C-Struct-Generator.
//
//  (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP<BR>
//  SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Auto-generated file by Redfish Schema C Structure Generator.
// https://github.com/DMTF/Redfish-Schema-C-Struct-Generator.
// Copyright Notice:
// Copyright 2019-2021 Distributed Management Task Force, Inc. All rights reserved.
// License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-JSON-C-Struct-Converter/blob/master/LICENSE.md
//

#ifndef EFI_REDFISHMANAGERACCOUNT_V1_4_3_CSTRUCT_H_
#define EFI_REDFISHMANAGERACCOUNT_V1_4_3_CSTRUCT_H_

#include "../../../include/RedfishDataTypeDef.h"
#include "../../../include/Redfish_ManagerAccount_v1_4_3_CS.h"

typedef RedfishManagerAccount_V1_4_3_ManagerAccount_CS EFI_REDFISH_MANAGERACCOUNT_V1_4_3_CS;

RedfishCS_status
Json_ManagerAccount_V1_4_3_To_CS (RedfishCS_char *JsonRawText, EFI_REDFISH_MANAGERACCOUNT_V1_4_3_CS **ReturnedCs);

RedfishCS_status
CS_To_ManagerAccount_V1_4_3_JSON (EFI_REDFISH_MANAGERACCOUNT_V1_4_3_CS *CSPtr, RedfishCS_char **JsonText);

RedfishCS_status
DestroyManagerAccount_V1_4_3_CS (EFI_REDFISH_MANAGERACCOUNT_V1_4_3_CS *CSPtr);

RedfishCS_status
DestroyManagerAccount_V1_4_3_Json (RedfishCS_char *JsonText);

#endif
