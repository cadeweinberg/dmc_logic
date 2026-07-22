# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

# it looks like we can define each of the structs as a C style struct and use the python Structs 
# interface to unpack the packet into a python tuple. This tuple can then be unpacked by the format string 
# in the result_types variable. We dont have the ability to support VLAs, but we can define the protocol
# for just the Limnmoco. where we have 8 motors.
#
# is there a "stringify" method that python uses, which we could override to provide a display of the 
# enumeration?


from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from ctypes import *
from enum import Enum, auto
from array import array

class DMCv2ReadState(Enum):
    Wait_D        = auto()
    Wait_F        = auto()
    Read_Header   = auto()
    Read_Payload  = auto()
    Read_Checksum = auto()

class DMCv2Type(Enum):
    DMC_MSG_HI                      = 0x0001
    DMC_MSG_DMX                     = 0x0020
    DMC_MSG_GIO_OUT                 = 0x0021
    DMC_MSG_GIO_IN                  = 0x0022
    DMC_MSG_GIO_CAM                 = 0x0023
    DMC_MSG_MOTOR_STATUS            = 0x0030
    DMC_MSG_MOTOR_MOVE              = 0x0031
    DMC_MSG_MOTOR_STOP              = 0x0032
    DMC_MSG_MOTOR_STOP_ALL          = 0x0033
    DMC_MSG_MOTOR_GET_POSITION      = 0x0034
    DMC_MSG_MOTOR_RESET_POSITION    = 0x0035
    DMC_MSG_MOTOR_JOG               = 0x0036
    DMC_MSG_MOTOR_CONFIGURE         = 0x0037
    DMC_MSG_MOTOR_SET_SPEED         = 0x0038
    DMC_MSG_MOTOR_SET_LIMITS        = 0x0039
    DMC_MSG_MOTOR_HARD_STOP         = 0x003A
    DMC_MSG_RT_UPLOAD_MOVE_BEGIN    = 0x0100
    DMC_MSG_RT_UPLOAD_MOVE_AXIS     = 0x0101
    DMC_MSG_RT_UPLOAD_MOVE_DMX      = 0x0102
    DMC_MSG_RT_UPLOAD_MOVE_END      = 0x0103
    DMC_MSG_RT_UPLOAD_MOVE_TRIGGERS = 0x0104
    DMC_MSG_RT_POSITION_FRAME       = 0x0110
    DMC_MSG_RT_RUN_MOVE             = 0x0111
    DMC_MSG_RT_SHOOT_FRAME          = 0x0112
    DMC_MSG_RT_SHOOT_FRAME2         = 0x0115
    DMC_MSG_RT_GO                   = 0x0113
    DMC_MSG_RT_END                  = 0x0114
    DMC_MSG_RT_STOP_LOOP            = 0x0116
    DMC_MSG_RT_JOG_ALL              = 0x0120
    DMC_MSG_VIRT_CONFIG             = 0x0200
    DMC_MSG_VIRT_MOVE               = 0x0201
    DMC_MSG_VIRT_STOP               = 0x0202
    DMC_MSG_VIRT_JOG                = 0x0203
    DMC_MSG_VIRT_GET_POSITION       = 0x0205
    DMC_MSG_VIRT_JOG_ON_LINE        = 0x0206
    DMC_MSG_VIRT_AIM_POINT          = 0x0207


# High level analyzers must subclass the HighLevelAnalyzer class.
class DMCv2(HighLevelAnalyzer):
    state            = DMCv2ReadState.Wait_D
    buffer           = array('B') # array of unsigned char
    length           = 0
    frame_start_time = None
    frame_end_time   = None

    # List of settings that a user can set for this High Level Analyzer.
    search_for = StringSetting() 

    dmc_header               = "<2BIH"
    dmc_check                = "H"
    dmc_ack                  = dmc_header + "H" + dmc_check
    dmc_hi                   = dmc_header + dmc_check
    dmc_device               = dmc_header + "32B3BBHBBBIIH" + dmc_check
    dmc_dmx                  = dmc_header + "BH" #FAM
    dmc_gio_out              = dmc_header + "L" + dmc_check
    dmc_gio_in               = dmc_header + "L" + dmc_check
    dmc_gio_cam              = dmc_header + "L" + dmc_check
    dmc_motor_status         = dmc_header + "LB" + dmc_check
    dmc_motor_move           = dmc_header + "Bi" + dmc_check
    dmc_motor_move_response  = dmc_header + "B" + dmc_check
    dmc_motor_stop           = dmc_header + "B" + dmc_check
    dmc_motor_stop_all       = dmc_header + "L" + dmc_check
    dmc_motor_get_position   = dmc_header + "L8i" + dmc_check
    dmc_motor_reset_position = dmc_header + "Bi" + dmc_check
    dmc_motor_jog            = dmc_header + "BHi" + dmc_check
    dmc_motor_configure      = dmc_header + "BB" + dmc_check
    dmc_motor_set_speed      = dmc_header + "BLL" + dmc_check
    dmc_motor_set_limits     = dmc_header + "BBLBLB" + dmc_check
    dmc_motor_hard_stop      = dmc_header + "BB" + dmc_check
    dmc_rt_upload_move_begin    = dmc_header + "LL" + dmc_check
    dmc_rt_upload_move_axis     = dmc_header + "BL" #FAM
    dmc_rt_upload_move_dmx      = dmc_header + "HL" #FAM
    dmc_rt_upload_move_triggers = dmc_header + "L" #FAM
    dmc_rt_upload_move_end      = dmc_header + dmc_check
    dmc_rt_position_frame       = dmc_header + "L" + dmc_check
    dmc_rt_run_move             = dmc_header + "LLLLLBLHHH" + dmc_check
    dmc_rt_shoot_frame          = dmc_header + "LBLH" # FAM
    dmc_rt_shoot_frame2         = dmc_header + "LLHH" # FAM
    dmc_rt_go                   = dmc_header
    dmc_rt_end                  = dmc_header
    dmc_rt_jog_all              = dmc_header + "Li"
    dmc_rt_stop_loop            = dmc_header
    dmc_virt_config             = dmc_header + "B" #FAM
    dmc_virt_config_boom_swing_track = dmc_header + "B23L" #FAM
    dmc_virt_config_swing_pan        = dmc_header + "BLLLL" + dmc_check
    dmc_virt_move                    = dmc_header + "Bi" + dmc_check
    dmc_virt_stop                    = dmc_header + "B" + dmc_check
    dmc_virt_jog                     = dmc_header + "BHi" + dmc_check
    dmc_virt_jog_on_line             = dmc_header + "BH" + dmc_check
    dmc_virt_get_position            = dmc_header + "6i" #FAM
    dmc_virt_aim_point               = dmc_header + "Biii" + dmc_check

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'dmc_header': {
            'format': 'Header: marker:{{data.marker_D}}{{data.marker_F}} id:{{data.id}} type:{{data.type}} length:{{data.length}}'
        },
        'dmc_ack': {
            'format': ''
        },
        'dmc_hi': {
            'format': ''
        }
    }

    def reset(self):
        buffer.clear()
        state            = DMCv2ReadState.Wait_F
        frame_start_time = None
        frame_end_time   = None

    def __init__(self):
        pass 

    # print out the different kinds of packet
    def handle(self):
        header = unpack(dmc_header, buffer)
        return AnalyzerFrame('dmc_header', frame_start_time, frame_end_time, {
            'marker_D': header[0],
            'marker_F': header[1],
            'id':       header[2],
            'type':     header[3],
            'length':   header[4]
        })

    def decode(self, frame: AnalyzerFrame):
        b = frame.data['data']
        match state:
            case DMCv2ReadState.Wait_D:
                try:
                    c = b.decode('ascii')

                    if c == 'D':
                        buffer.append(c)
                        state            = DMCv2ReadState.Wait_F
                        frame_start_time = frame.start_time
                except:
                    reset()
                    return

            case DMCv2ReadState.Wait_F:
                try:
                    c = d.decode('ascii')

                    if c == 'F':
                        buffer.append(c)
                        state = DMCv2ReadState.ReadHeader
                        return
                    elif c == 'D':
                        return
                except:
                    reset()
                    return
                reset()
                return

            case DMCv2ReadState.ReadHeader:
                buffer.append(c)

                if buffer.__len__() == 10:
                    length = int.from_bytes(buffer[8:9:1], byteorder='little', signed=False)
                    total  = length + 12

                    if total >= 2048:
                        reset()
                        return

                    state = DMCv2ReadState.ReadPayload
                    length = total

            case DMCv2ReadState.ReadPayload:
                buffer.append(c)

                if buffer.__len__() < length:
                    return
                # we are here, that means we can print out the packet contents 
                frame_end_time = frame.end_time
                reset()
                return handle()












