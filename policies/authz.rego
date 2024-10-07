package submission

import future.keywords.in  # Enable the future 'in' keyword support

input_oe := input.action.fields_input_action_permission.oe
input_lob := input.action.fields_input_action_permission.lob
input_lta_duration := input.action.fields_input_auth_grid.lta.duration

region_oes := {
    "Asia": ["AGCS Singapore", "AGCS Japan"],
    "SouthernEurope": ["AGCS Germany"]
}

# Format: [lowerbound normal A, upperbound normal A, upperbound LTA]
lta_bounds_list := {
    "d2": [0, 24, null],
    "d1": [0, 24, null],
    "c2": [0, 18, 24],
    "c1": [0, 18, 24],
    "b2": [0, 18, 24],
    "b1": [0, 18, 24],
    "a2": [0, 18, 24],
    "a1": [0, 18, 24]
}

default create_allow := false

create_allow if {
    some role in input.subject.role
    action_allowed(role, input_oe, input_lob)
    level := role.authorityGrid[0].level
    in_normal_bounds(input_lta_duration, lta_bounds_list[level])
}

# Check if action is allowed for 'uw' role
action_allowed(role, oe, lob) if {
    role.position == "uw"
    role.oe == oe
    role.lob == lob
}

# Check if action is allowed for 'arc' role
action_allowed(role, oe, lob) if {
    input.action.name == "read"
    role.position == "arc"
    role.oe == oe
    role.lob == lob
}

# Allow if we read, and there is an "uw" role in the same region
action_allowed(_, oe, _) if {
    input.action.name == "read"
    some otherRole in input.subject.role
    otherRole.position == "uw"
    oe in region_oes[otherRole.region]
}

# Allow if we read, and there is an "arc" role in the same region
action_allowed(_, oe, _) if {
    input.action.name == "read"
    some otherRole in input.subject.role
    otherRole.position == "arc"
    oe in region_oes[otherRole.region]
}

# Check if duration is within LTA bounds
in_lta_bounds(duration, bounds) := {
    bounds[2] != null
    duration >= bounds[1]
    duration <= bounds[2]
} else {
    bounds[2] == null
    duration >= bounds[1]
}

# Check if duration is within normal bounds
in_normal_bounds(duration, bounds) := {
    duration <= bounds[1]
}

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
    some role in input.subject.role
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
