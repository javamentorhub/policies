package submission

import rego.v1

input_oe := input.action.fields_input_action_permission.oe

input_lob := input.action.fields_input_action_permission.lob

input_lta_duration := input.action.fields_input_auth_grid.lta.duration

region_oes := {
        "Asia": ["AGCS Singapore", "AGCS Japan"],
        "SouthernEurope": ["AGCS Germany"]
}


# format: [lowerbound normal A, upperbound normal A, upperbound LTA]
lta_bounds_list := {
        # level | min period | max peeriod without ref. | max per with ref.
        # null = no limit
	    "d2": [0, 24, null],
	    "d1": [0, 24, null],
        "c2": [0, 18, 24],
        "c1": [0, 18, 24],
        "b2": [0, 18, 24],
        "b1": [0, 18, 24],
        "a2": [0, 18, 24],
        "a1": [0, 18, 24]
}
 
# Allow the creation of the submission if there is a role with which the user has the correct permissions and
# the grid is filled accordingly.
default create_allow := false

create_allow if {
	# initialize the loop going through the user's roles
	some role in input.subject.role

	# first check if the user is allowed this action for this OE, LoB
	action_allowed(role, input_oe, input_lob) #Is action erlaubt?


	# check if the duration is allowed for that level
	#level := role.authorityGrid[0].level   
	#in_normal_bounds(input_lta_duration, lta_bounds_list[level])
   
}

# check if action is allowed
action_allowed(role, oe, lob) if {
	role.position == "uw"
	role.oe == oe
	role.lob == lob
}


# check if action is allowed
action_allowed(role, oe, lob) if {
	input.action.name == "read"
	role.position == "arc"
	role.oe == oe
	role.lob == lob
}

# If we read, allow if there is an "uw" role in the same Region
action_allowed(_, oe, _) if {
        input.action.name == "read"
        some otherRole in input.subject.role
	otherRole.position == "uw"
        oe in region_oes[otherRole.region]
}

 # If we read, allow if there is an "arc" role in the same Region
action_allowed(_, oe, _) if {
        input.action.name == "read"
        some otherRole in input.subject.role
	otherRole.position == "arc"
        oe in region_oes[otherRole.region]
}

#Added during live
#action_allowed(_, _, lob) if {
#        input.action.name == "read"
#        some otherRole in input.subject.role
#		otherRole.position == "arc"
#		lob == otherRole.lob
#}

in_lta_bounds(duration, bounds) := true if {
        bounds[2] != null
        duration >= bounds[1]
        duration <= bounds[2]
} else := true if {
        bounds[2] == null
        duration >= bounds[1]
} else := false

in_normal_bounds(duration, bounds) := true if {
	duration <= bounds[1]
} else := false

default create_error_message := "Action not allowed!"

create_error_message := "" if {
	create_allow
} else := "According to your issued Authorities, you have exceeded the max. policy period. Thus, a referral to the Global Property Head is required pre-quoting!" if {
	some role in input.subject.role
        level := role.authorityGrid[0].level
	action_allowed(role, input_oe, input_lob)
        not in_normal_bounds(input_lta_duration, lta_bounds_list[level])
        in_lta_bounds(input_lta_duration, lta_bounds_list[level])
} else := "According to your issued Authorities, you have exceeded the max. policy period. You are not allowed to create an LTA this long, referral not possible." if {
        some role in input.subject.role
        level := role.authorityGrid[0].level
	action_allowed(role, input_oe, input_lob)
        not in_normal_bounds(input_lta_duration, lta_bounds_list[level])
        not in_lta_bounds(input_lta_duration, lta_bounds_list[level])
}

default create_error_type := "action_error"

create_error_type := "" if {
	create_error_message == ""
} else := "grid_error" if {
	create_error_message == "According to your issued Authorities, you have exceeded the max. policy period. You are not allowed to create an LTA this long, referral not possible."
} else := "grid_error" if {
        create_error_message == "According to your issued Authorities, you have exceeded the max. policy period. Thus, a referral to the Global Property Head is required pre-quoting!"
}

create_output := {
	"result": create_allow,
	"error_message": create_error_message,
	"error_type": create_error_type,
}

default read_allow := false

read_allow if {
	# initialize the loop going through the user's roles
	some role in input.subject.role

	# only check if the user is allowed this action for this OE, LoB
	action_allowed(role, input_oe, input_lob)
}

default read_error_message := "Action not allowed!"

read_error_message := "" if {
	read_allow
}

default read_error_type := "action_error"

read_error_type := "" if {
	read_error_message == ""
}

read_output := {
	"result": read_allow,
	"error_message": read_error_message,
	"error_type": read_error_type,
}
