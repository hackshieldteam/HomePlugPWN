# -*- coding: utf-8 -*-

from layerscapy.HomePlugGP import *

"""
    Copyright (C) HomePlugSG Layer for Scapy by FlUxIuS (Sebastien Dudek)
"""

########################## HomePlug GP extend for SG ###############################

HomePlugSGTypes = { 0xA400 : "VS_UART_CMD_Req",
                    0xA401 : "VS_UART_CMD_Cnf" }

QualcommTypeList.update(HomePlugSGTypes)

######################################################################
# UART
######################################################################

class VS_UART_CMD_REQ(Packet):
    name = "VS_UART_CMD_REQ"
    fields_desc = [ FieldLenField("UDataLen", None, count_of="UData", fmt="H"),
                    StrLenField("UData", "UartCommand\x00", length_from = lambda pkt: pkt.UDataLen),
            ]

class VS_UART_CMD_REQ(Packet):
    name = "VS_UART_CMD_CNF"
    fields_desc = [ StrFixedLenField("reserved", "\x00", 6),
                    FieldLenField("UDataLen", None, count_of="UData", fmt="H"),
                    StrLenField("UData", "UartCommand\x00", length_from = lambda pkt: pkt.UDataLen),
            ]

########################### END #######################################

bind_layers( HomePlugAV, VS_UART_CMD_REQ,  { "HPtype" : 0xA400 } )
