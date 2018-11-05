//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gesrule_h__
#define __gesrule_h__

#include "gesruledef.h"

namespace GesRule {

    enum ActionType {
        actRead,
        actModify
    };

	enum SubjectType {
		sbtExec			=  0,
		sbtScript		=  1
	};

	Rule::RuleResult Apply(unsigned long &Subject, ModelType &SubjectModel, ConfidentLevel &SubjectLevel,
                     unsigned long &Object, ModelType &ObjectModel, ConfidentLevel &ObjectLevel, 
                     ObjectType ObjType, ActionType Action, Rule::AefCommand &Command);
};

#endif // __gesrule_h__