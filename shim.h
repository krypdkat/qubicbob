#pragma once
#include "GlobalVar.h"

#define MRB_Data                   (GS().MRB_Data)
#define MRB_Request                (GS().MRB_Request)
#define requestMapperFrom          (GS().requestMapperFrom)
#define requestMapperTo            (GS().requestMapperTo)
#define gCurrentProcessingTick     (GS().gCurrentProcessingTick)
#define gCurrentProcessingEpoch    (GS().gCurrentProcessingEpoch)
#define gInitialTick               (GS().gInitialTick)
#define gCurrentLoggingEventTick   (GS().gCurrentLoggingEventTick)
#define gCurrentVerifyLoggingTick  (GS().gCurrentVerifyLoggingTick)
#define gCurrentIndexingTick       (GS().gCurrentIndexingTick)
#define computorsList              (GS().computorsList)

#define spectrum                   ((EntityRecord*)GS().spectrum)
#define assets                     ((AssetRecord*)GS().assets)
#define assetChangeFlags           (GS().assetChangeFlags)
#define spectrumChangeFlags        (GS().spectrumChangeFlags)
#define spectrumDigests            (GS().spectrumDigests)
#define assetDigests               (GS().assetDigests)
#define refetchFromId              (GS().refetchFromId)
#define refetchToId                (GS().refetchToId)
