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

#ifndef EFI_REDFISHMETRICREPORTDEFINITION_V1_0_0_CSTRUCT_H_
#define EFI_REDFISHMETRICREPORTDEFINITION_V1_0_0_CSTRUCT_H_

#include "../../../include/RedfishDataTypeDef.h"
#include "../../../include/Redfish_MetricReportDefinition_v1_0_0_CS.h"

typedef RedfishMetricReportDefinition_V1_0_0_MetricReportDefinition_CS EFI_REDFISH_METRICREPORTDEFINITION_V1_0_0_CS;

RedfishCS_status
Json_MetricReportDefinition_V1_0_0_To_CS (RedfishCS_char *JsonRawText, EFI_REDFISH_METRICREPORTDEFINITION_V1_0_0_CS **ReturnedCs);

RedfishCS_status
CS_To_MetricReportDefinition_V1_0_0_JSON (EFI_REDFISH_METRICREPORTDEFINITION_V1_0_0_CS *CSPtr, RedfishCS_char **JsonText);

RedfishCS_status
DestroyMetricReportDefinition_V1_0_0_CS (EFI_REDFISH_METRICREPORTDEFINITION_V1_0_0_CS *CSPtr);

RedfishCS_status
DestroyMetricReportDefinition_V1_0_0_Json (RedfishCS_char *JsonText);

#endif
