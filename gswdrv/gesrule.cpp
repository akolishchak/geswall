//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "gesrule.h"

Rule::RuleResult GesRule::Apply(unsigned long &Subject, ModelType &SubjectModel, ConfidentLevel &SubjectLevel,
                     unsigned long &Object, ModelType &ObjectModel, ConfidentLevel &ObjectLevel, 
                     ObjectType ObjType, ActionType Action, Rule::AefCommand &Command)
{
    Command = Rule::aefNone;

    //
    // Confidentiality model
    //
    Rule::RuleResult MC = Rule::rurBlockAction;
    bool bConfidentiality = ( ObjectLevel <= SubjectLevel );
	if ( ObjectLevel == cflLeakSource && SubjectLevel == cflSecret ) {
		SubjectLevel = cflClassified;
		Command = Rule::aefSaveSubjectInfo;
	}

    if ( bConfidentiality ) {
        MC = Rule::rurAllowAction;
    }

    // 
    // Integrity model
    //
    Rule::RuleResult MI = Rule::rurBlockModify;
    bool bIntegrity = ( Action == actRead ) || 
                      ( ObjectModel <= SubjectModel );

    if ( bConfidentiality && bIntegrity ) {
        MI = Rule::rurAllowAction;
        if ( SubjectModel > modThreatPoint && 
			 ( ObjType == obtStorage || ObjType == obtIO ) &&
			 ObjectModel == modThreatPoint  ) {
            SubjectModel = modThreatPoint;
			SubjectLevel = cflClassified;
            Command = Rule::aefSaveSubjectInfo;
        }
    }

    return min(MI, MC);
}
