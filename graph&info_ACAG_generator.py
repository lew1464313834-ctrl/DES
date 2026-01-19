from generate_ACAG_helper import HelperFunctionColledtion
class ACAGSystem:
    #生成ACAG转移关系
    # 包括环境状态Ye（environment_ACAG_state):(监督器预估集，攻击者预估集，受控系统当前状态)
    # 攻击状态Ya(attacker_ACAG_state)            
    @staticmethod
    def generate_ACAG_transition(event_system, 
                                 event_attacker_observable,
                                 event_attacker_unobservable,
                                 event_vulnerable,
                                 event_attacker_alterable,
                                 event_supervisor_observable,
                                 event_supervisor_unobservable,
                                 event_supervisor_controllable,
                                 transition_closed_loop_system,
                                 transition_origin_system,
                                 state_initial_origin,
                                 state_initial_closed_loop_system
                                 ):
        environment_ACAG_state=set()
        attacker_ACAG_state=set()
        all_ACAG_transition = {}
        # 1. 生成ACAG初始状态(初始状态一定是环境状态)
        initial_ACAG_state=()
        #监督器的初始估计集
        initial_estimation_supervisor=ACAGSystem.cal_unobservable_reach(
            state_initial_closed_loop_system, 
            transition_closed_loop_system, 
            event_supervisor_unobservable
        )
        #攻击者的初始估计集
        initial_estimation_attacker=ACAGSystem.cal_unobservable_reach(
            state_initial_origin, 
            transition_origin_system, 
            event_attacker_unobservable
        )
        #创建初始状态
        initial_ACAG_state=(initial_estimation_supervisor,initial_estimation_attacker,state_initial_closed_loop_system)
        environment_ACAG_state.add(initial_ACAG_state)
        # 2. 计算环境状态-攻击状态转换关系
        def cal_transition_ACAG_environment_to_attacker(current_environment_ACAG_state,event):
            if (current_environment_ACAG_state=={'AX'}):
                return
            #判断事件是否可被篡改
            events_possible=ACAGSystem.tamper_events(
                event_vulnerable,
                event_attacker_alterable,
                event
            )
            #输出攻击环境下的事件（可被篡改的事件输出所有篡改后的事件，不可被篡改的事件输出自身）
            next_attacker_ACAG_state=current_environment_ACAG_state+events_possible
            return next_attacker_ACAG_state
        #3.计算攻击状态-环境状态转换关系
        def cal_transition_ACAG_attacker_to_environment(current_attacker_ACAG_state,
                                                        transition_closed_loop_system,
                                                        transition_supervisor,
                                                        ):
            # 获取当前攻击状态的分量
            current_estimation_supervisor, current_estimation_attacker, closed_loop_system_state,event_possible = current_attacker_ACAG_state
            #更新监督器估计集
            
        return all_ACAG_transition