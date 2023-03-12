package edu

default has_gwg_education = false

has_gwg_education {
    data.education[input.user][_] == "gwg"
}