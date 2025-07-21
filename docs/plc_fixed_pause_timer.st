PROGRAM program0
  VAR
    cmd AT %MW0 : INT;
    status_out AT %QW102 : INT;
    tank_level AT %IW100 : INT;
    alarm_flag AT %IX100.0 : BOOL;
    valve_inlet AT %QX100.0 : BOOL;
    valve_outlet AT %QX100.1 : BOOL;
    mixer_ctrl AT %QX100.2 : BOOL;
    mixing_done AT %QX100.4 : BOOL;
  END_VAR
  VAR
    paused : BOOL := FALSE;
    mixing_started : BOOL := FALSE;
    mixing_timer : TON;
    emergency_held : BOOL := FALSE;
    stop_btn : BOOL;
    state : INT := 0;
    prev_state : INT := 0;
  END_VAR

  (* === EMERGENCY STOP HANDLER === *)
  IF alarm_flag OR cmd = 200 THEN
    valve_inlet := FALSE;
    valve_outlet := FALSE;
    mixer_ctrl := FALSE;
    mixing_timer(IN := FALSE);
    emergency_held := TRUE;
    paused := FALSE;
    state := 5;
  END_IF;

  (* === RESET HANDLER === *)
  IF cmd = 300 THEN
    emergency_held := FALSE;
    paused := FALSE;
    mixing_started := FALSE;
    mixing_timer(IN := FALSE);
    valve_inlet := FALSE;
    valve_outlet := FALSE;
    mixer_ctrl := FALSE;
    mixing_done := FALSE;
    tank_level := 0;
    state := 0;
  END_IF;

  (* === PAUSE HANDLER === *)
  IF cmd = 100 AND NOT paused AND state <> 0 AND state <> 5 AND state <> 6 THEN
    prev_state := state;
    paused := TRUE;
    valve_inlet := FALSE;
    valve_outlet := FALSE;
    state := 6;
  END_IF;

  (* === RESUME HANDLER === *)
  IF cmd = 400 AND paused THEN
    paused := FALSE;
    IF prev_state = 2 THEN
      mixing_started := FALSE;
    END_IF;
    state := prev_state;
  END_IF;

  (* === STATE MACHINE === *)
  IF NOT paused AND NOT emergency_held THEN
    CASE state OF
      0:
        valve_inlet := FALSE;
        valve_outlet := FALSE;
        mixer_ctrl := FALSE;
        mixing_done := FALSE;
        mixing_timer(IN := FALSE);
        IF cmd = 500 THEN
          state := 1;
        END_IF;

      1:
        valve_inlet := TRUE;
        valve_outlet := FALSE;
        IF tank_level >= 80 THEN
          valve_inlet := FALSE;
          mixing_timer(IN := TRUE, PT := T#30S);
          mixing_started := TRUE;
          mixer_ctrl := TRUE;
          state := 2;
        END_IF;

      2:
        mixing_timer(IN := TRUE);
        mixer_ctrl := TRUE;
        IF mixing_timer.Q THEN
          mixer_ctrl := FALSE;
          mixing_done := TRUE;
          mixing_started := FALSE;
          state := 3;
        END_IF;

      3:
        IF paused THEN
          valve_outlet := FALSE;
        ELSE
          valve_inlet := FALSE;
          valve_outlet := TRUE;
          IF tank_level <= 20 THEN
            valve_outlet := FALSE;
            state := 0;
          END_IF;
        END_IF;

      4:
        mixer_ctrl := FALSE;
        mixing_done := FALSE;
        valve_outlet := FALSE;
	IF cmd = 500 THEN
  		state := 1;
	END_IF;

      5:
        valve_inlet := FALSE;
        valve_outlet := FALSE;
        mixer_ctrl := FALSE;
        mixing_timer(IN := FALSE);

      6:
        valve_inlet := FALSE;
        valve_outlet := FALSE;
        mixer_ctrl := FALSE;
        mixing_timer(IN := FALSE);
    END_CASE;
  END_IF;

  cmd := 0;
  status_out := state;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : program0;
  END_RESOURCE
END_CONFIGURATION

(*DBG:char md5[] = "9bc9ab015b8d07dbac2131c025d1b41d";*)
(*DBG:/**)
(*DBG: * This file is part of OpenPLC Runtime*)
(*DBG: **)
(*DBG: * Copyright (C) 2023 Autonomy, GP Orcullo*)
(*DBG: * Based on the work by GP Orcullo on Beremiz for uC*)
(*DBG: **)
(*DBG: * This program is free software; you can redistribute it and/or*)
(*DBG: * modify it under the terms of the GNU General Public License*)
(*DBG: * as published by the Free Software Foundation; either version 2*)
(*DBG: * of the License, or (at your option) any later version.*)
(*DBG: **)
(*DBG: * This program is distributed in the hope that it will be useful,*)
(*DBG: * but WITHOUT ANY WARRANTY; without even the implied warranty of*)
(*DBG: * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the*)
(*DBG: * GNU General Public License for more details.*)
(*DBG: **)
(*DBG: * You should have received a copy of the GNU General Public License*)
(*DBG: * along with this program; If not, see <http://www.gnu.org/licenses/>.*)
(*DBG: **)
(*DBG: */*)
(*DBG:*)
(*DBG:#include <stdbool.h>*)
(*DBG:*)
(*DBG:#include "iec_types_all.h"*)
(*DBG:#include "POUS.h"*)
(*DBG:*)
(*DBG:#define SAME_ENDIANNESS      0*)
(*DBG:#define REVERSE_ENDIANNESS   1*)
(*DBG:*)
(*DBG:uint8_t endianness;*)
(*DBG:*)
(*DBG:*)
(*DBG:extern PROGRAM0 RES0__INSTANCE0;*)
(*DBG:*)
(*DBG:static const struct {*)
(*DBG:    void *ptr;*)
(*DBG:    __IEC_types_enum type;*)
(*DBG:} debug_vars[] = {*)
(*DBG:    {&(RES0__INSTANCE0.CMD), INT_O_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.STATUS_OUT), INT_O_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.TANK_LEVEL), INT_P_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.ALARM_FLAG), BOOL_P_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.VALVE_INLET), BOOL_O_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.VALVE_OUTLET), BOOL_O_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXER_CTRL), BOOL_O_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_DONE), BOOL_O_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.PAUSED), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_STARTED), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.EN), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.ENO), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.IN), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.PT), TIME_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.Q), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.ET), TIME_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.STATE), SINT_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.PREV_IN), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.CURRENT_TIME), TIME_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.MIXING_TIMER.START_TIME), TIME_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.EMERGENCY_HELD), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.STOP_BTN), BOOL_ENUM},*)
(*DBG:    {&(RES0__INSTANCE0.STATE), INT_ENUM},*)
(*DBG:};*)
(*DBG:*)
(*DBG:#define VAR_COUNT               23*)
(*DBG:*)
(*DBG:uint16_t get_var_count(void)*)
(*DBG:{*)
(*DBG:    return VAR_COUNT;*)
(*DBG:}*)
(*DBG:*)
(*DBG:size_t get_var_size(size_t idx)*)
(*DBG:{*)
(*DBG:    if (idx >= VAR_COUNT)*)
(*DBG:    {*)
(*DBG:        return 0;*)
(*DBG:    }*)
(*DBG:    switch (debug_vars[idx].type) {*)
(*DBG:    case BOOL_ENUM:*)
(*DBG:    case BOOL_O_ENUM:*)
(*DBG:    case BOOL_P_ENUM:*)
(*DBG:        return sizeof(BOOL);*)
(*DBG:    case TIME_ENUM:*)
(*DBG:        return sizeof(TIME);*)
(*DBG:    case SINT_ENUM:*)
(*DBG:        return sizeof(SINT);*)
(*DBG:    case INT_ENUM:*)
(*DBG:    case INT_O_ENUM:*)
(*DBG:    case INT_P_ENUM:*)
(*DBG:        return sizeof(INT);*)
(*DBG:    default:*)
(*DBG:        return 0;*)
(*DBG:    }*)
(*DBG:}*)
(*DBG:*)
(*DBG:void *get_var_addr(size_t idx)*)
(*DBG:{*)
(*DBG:    void *ptr = debug_vars[idx].ptr;*)
(*DBG:*)
(*DBG:    switch (debug_vars[idx].type) {*)
(*DBG:    case BOOL_ENUM:*)
(*DBG:        return (void *)&((__IEC_BOOL_t *) ptr)->value;*)
(*DBG:    case BOOL_O_ENUM:*)
(*DBG:    case BOOL_P_ENUM:*)
(*DBG:        return (void *)((((__IEC_BOOL_p *) ptr)->flags & __IEC_FORCE_FLAG) *)
(*DBG:                        ? &(((__IEC_BOOL_p *) ptr)->fvalue) *)
(*DBG:                        : ((__IEC_BOOL_p *) ptr)->value);*)
(*DBG:    case TIME_ENUM:*)
(*DBG:        return (void *)&((__IEC_TIME_t *) ptr)->value;*)
(*DBG:    case SINT_ENUM:*)
(*DBG:        return (void *)&((__IEC_SINT_t *) ptr)->value;*)
(*DBG:    case INT_ENUM:*)
(*DBG:        return (void *)&((__IEC_INT_t *) ptr)->value;*)
(*DBG:    case INT_O_ENUM:*)
(*DBG:    case INT_P_ENUM:*)
(*DBG:        return (void *)((((__IEC_INT_p *) ptr)->flags & __IEC_FORCE_FLAG) *)
(*DBG:                        ? &(((__IEC_INT_p *) ptr)->fvalue) *)
(*DBG:                        : ((__IEC_INT_p *) ptr)->value);*)
(*DBG:    default:*)
(*DBG:        return 0;*)
(*DBG:    }*)
(*DBG:}*)
(*DBG:*)
(*DBG:void force_var(size_t idx, bool forced, void *val)*)
(*DBG:{*)
(*DBG:    void *ptr = debug_vars[idx].ptr;*)
(*DBG:*)
(*DBG:    if (forced) {*)
(*DBG:        size_t var_size = get_var_size(idx);*)
(*DBG:        switch (debug_vars[idx].type) {*)
(*DBG:        case BOOL_ENUM: {*)
(*DBG:            memcpy(&((__IEC_BOOL_t *) ptr)->value, val, var_size);*)
(*DBG:            //((__IEC_BOOL_t *) ptr)->value = *((BOOL *) val);*)
(*DBG:            ((__IEC_BOOL_t *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        case BOOL_O_ENUM: {*)
(*DBG:            memcpy((((__IEC_BOOL_p *) ptr)->value), val, var_size);*)
(*DBG:            //*(((__IEC_BOOL_p *) ptr)->value) = *((BOOL *) val);*)
(*DBG:            ((__IEC_BOOL_p *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        case BOOL_P_ENUM: {*)
(*DBG:            memcpy(&((__IEC_BOOL_p *) ptr)->fvalue, val, var_size);*)
(*DBG:            //((__IEC_BOOL_p *) ptr)->fvalue = *((BOOL *) val);*)
(*DBG:            ((__IEC_BOOL_p *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        case TIME_ENUM: {*)
(*DBG:            memcpy(&((__IEC_TIME_t *) ptr)->value, val, var_size);*)
(*DBG:            //((__IEC_TIME_t *) ptr)->value = *((TIME *) val);*)
(*DBG:            ((__IEC_TIME_t *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        case SINT_ENUM: {*)
(*DBG:            memcpy(&((__IEC_SINT_t *) ptr)->value, val, var_size);*)
(*DBG:            //((__IEC_SINT_t *) ptr)->value = *((SINT *) val);*)
(*DBG:            ((__IEC_SINT_t *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        case INT_ENUM: {*)
(*DBG:            memcpy(&((__IEC_INT_t *) ptr)->value, val, var_size);*)
(*DBG:            //((__IEC_INT_t *) ptr)->value = *((INT *) val);*)
(*DBG:            ((__IEC_INT_t *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        case INT_O_ENUM: {*)
(*DBG:            memcpy((((__IEC_INT_p *) ptr)->value), val, var_size);*)
(*DBG:            //*(((__IEC_INT_p *) ptr)->value) = *((INT *) val);*)
(*DBG:            ((__IEC_INT_p *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        case INT_P_ENUM: {*)
(*DBG:            memcpy(&((__IEC_INT_p *) ptr)->fvalue, val, var_size);*)
(*DBG:            //((__IEC_INT_p *) ptr)->fvalue = *((INT *) val);*)
(*DBG:            ((__IEC_INT_p *) ptr)->flags |= __IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:        default:*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:    } else {*)
(*DBG:        switch (debug_vars[idx].type) {*)
(*DBG:        case BOOL_ENUM:*)
(*DBG:            ((__IEC_BOOL_t *) ptr)->flags &= ~__IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        case BOOL_O_ENUM:*)
(*DBG:        case BOOL_P_ENUM:*)
(*DBG:            ((__IEC_BOOL_p *) ptr)->flags &= ~__IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        case TIME_ENUM:*)
(*DBG:            ((__IEC_TIME_t *) ptr)->flags &= ~__IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        case SINT_ENUM:*)
(*DBG:            ((__IEC_SINT_t *) ptr)->flags &= ~__IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        case INT_ENUM:*)
(*DBG:            ((__IEC_INT_t *) ptr)->flags &= ~__IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        case INT_O_ENUM:*)
(*DBG:        case INT_P_ENUM:*)
(*DBG:            ((__IEC_INT_p *) ptr)->flags &= ~__IEC_FORCE_FLAG;*)
(*DBG:            break;*)
(*DBG:        default:*)
(*DBG:            break;*)
(*DBG:        }*)
(*DBG:    }*)
(*DBG:}*)
(*DBG:*)
(*DBG:void swap_bytes(void *ptr, size_t size) *)
(*DBG:{*)
(*DBG:    uint8_t *bytePtr = (uint8_t *)ptr;*)
(*DBG:    size_t i;*)
(*DBG:    for (i = 0; i < size / 2; ++i) *)
(*DBG:    {*)
(*DBG:        uint8_t temp = bytePtr[i];*)
(*DBG:        bytePtr[i] = bytePtr[size - 1 - i];*)
(*DBG:        bytePtr[size - 1 - i] = temp;*)
(*DBG:    }*)
(*DBG:}*)
(*DBG:*)
(*DBG:void trace_reset(void)*)
(*DBG:{*)
(*DBG:    for (size_t i=0; i < VAR_COUNT; i++) *)
(*DBG:    {*)
(*DBG:        force_var(i, false, 0);*)
(*DBG:    }*)
(*DBG:}*)
(*DBG:*)
(*DBG:void set_trace(size_t idx, bool forced, void *val)*)
(*DBG:{*)
(*DBG:    if (idx >= 0 && idx < VAR_COUNT) *)
(*DBG:    {*)
(*DBG:        if (endianness == REVERSE_ENDIANNESS)*)
(*DBG:        {*)
(*DBG:            // Aaaaarghhhh... Stupid AVR is Big Endian.*)
(*DBG:            swap_bytes(val, get_var_size(idx));*)
(*DBG:        }*)
(*DBG:*)
(*DBG:        force_var(idx, forced, val);*)
(*DBG:    }*)
(*DBG:}*)
(*DBG:*)
(*DBG:void set_endianness(uint8_t value)*)
(*DBG:{*)
(*DBG:    if (value == SAME_ENDIANNESS || value == REVERSE_ENDIANNESS)*)
(*DBG:    {*)
(*DBG:        endianness = value;*)
(*DBG:    }*)
(*DBG:}*)
(*DBG:*)