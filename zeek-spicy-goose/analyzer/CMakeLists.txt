spicy_add_analyzer(
    NAME spicy_GOOSE
    PACKAGE_NAME GOOSE
    SOURCES spicy_goose.spicy spicy_goose.evt zeek_spicy_goose.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
