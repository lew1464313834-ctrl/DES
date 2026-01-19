from system_DFA_basic import SystemAssumptions, ClosedLoopSystem
from generate_ACAG_helper import GenerateACAGFunctionTools
from generate_ACAG_generator import ACAGSystemCreater

#===== 定义系统假设 =====
assumption = SystemAssumptions(
    state_oringin_system = {0, 1, 2, 3, 4, 5, 6, 7, 8},
    state_supervisor = {0, 1, 2},
    state_initial_origin_ststem = {0},
    state_initial_supervisor = {0},
    state_system_secret = {5},
    event_system =  {"o1", "o2", "o3", "o4", "uo1","uo2","uo3","empty"},
    event_attacker_observable = {"o2", "o3", "o4"},
    event_supervisor_observable = {"o1", "o2", "o3"},
    event_supervisor_controllable = {"o3","uo3"},
    event_vulnerable = {"o2","o3"},
    event_alterable = {"o2","o3", "empty"},
    transition_origin_system = {
            # ---------------------------------
            # state 0
            # ---------------------------------
            (0, "o1"): 1,
            (0, "o2"): 3,
            (0, "o3"): 7,
            (0, "empty"): 0,

            # ---------------------------------
            # state 1
            # ---------------------------------
            (1, "uo2"): 2,
            (1, "empty"): 1,

            # ---------------------------------
            # state 2
            # ---------------------------------
            (2, "o1"): 5,
            (2, "empty"): 2,

            # ---------------------------------
            # state 3
            # ---------------------------------
            (3, "o4"): 6,
            (3, "empty"): 3,

            # ---------------------------------
            # state 4
            # ---------------------------------
            (4, "o2"): 1,
            (4, "o1"): 6,
            (4, "empty"): 4,

            # ---------------------------------
            # state 5
            # ---------------------------------
            (5, "o4"): 0,
            (5, "empty"): 5,

            # ---------------------------------
            # state 6
            # ---------------------------------
            (6, "uo3"): 7,
            (6, "empty"): 6,

            # ---------------------------------
            # state 7
            # ---------------------------------
            (7, "o3"): 8,
            (7,"uo1"):4,
            (7, "empty"): 7,

            # ---------------------------------
            # state 8
            # ---------------------------------
            (8, "o2"):5,
            (8, "o3"): 4,
            (8, "empty"): 8
        },
        transition_supervisor = {
            # =========================
            # supervisor state z0
            # =========================
            (0, "o1"): 0,
            (0, "o2"): 2,
            (0, "o3"): 1,
            (0, "o4"): 0,
            (0, "uo1"): 0,
            (0, "uo2"): 0,
            (0, "uo3"): 0,
            (0, "empty"): 0,

            # =========================
            # supervisor state z1
            # =========================
            (1, "o1"): 1,
            (1, "o2"): 1,
            (1, "o4"): 1,
            (1, "uo1"): 1,
            (1, "uo2"): 1,
            (1, "uo3"): 1,
            (1, "empty"): 1,

            # =========================
            # supervisor state z2
            # =========================
            (2, "o1"): 2,
            (2, "o2"): 2,
            (2, "o3"): 2,
            (2, "o4"): 2,
            (2, "uo1"): 2,
            (2, "uo2"): 2,
            (2, "empty"): 2,
        }
)

#=====主程序=====
if __name__ == "__main__":
    #1.闭环系统
    #1.0 生成攻击者和监督器的不可观测事件集
    event_unobservable_supervisor=ClosedLoopSystem.generate_unobservable_events(
        assumption.event_system,
        assumption.event_supervisor_observable
    )
    print("监督器不可观测事件:", event_unobservable_supervisor)
    print("="*60)
    event_unobservable_attacker=ClosedLoopSystem.generate_unobservable_events(
        assumption.event_system,
        assumption.event_attacker_observable
    )
    print("攻击者不可观测事件:", event_unobservable_attacker)
    print("="*60)
    #1.1 生成闭环系统状态集合
    states_closed_loop_system=ClosedLoopSystem.generate_states_closed_loop_system(assumption.state_oringin_system,
                                                            assumption.state_initial_origin_ststem,
                                                            assumption.state_initial_supervisor,
                                                            assumption.event_system,
                                                            assumption.transition_origin_system,
                                                            assumption.transition_supervisor
                                                            )
    print("闭环系统状态集合:", states_closed_loop_system)
    print("="*60)
    #1.2 生成闭环转换关系
    transition_closed_loop_system=ClosedLoopSystem.generate_transition_closed_loop_system(assumption.state_oringin_system,
                                                            assumption.state_initial_origin_ststem,
                                                            assumption.state_initial_supervisor,
                                                            assumption.event_system,
                                                            assumption.transition_origin_system,
                                                            assumption.transition_supervisor
                                                            )
    print("闭环转换关系:", transition_closed_loop_system)
    print("="*60)
    # 1.3 绘制闭环系统图
    # 闭环系统初始状态
    state_initial_closed_loop_system = ClosedLoopSystem.generate_states_initial_closed_loop_system(
        assumption.state_initial_supervisor,
        assumption.state_initial_origin_ststem,
        states_closed_loop_system
    )
    print("初始状态:", state_initial_closed_loop_system)
    print("="*60)
    closed_loop_graph = ClosedLoopSystem.generate_closed_loop_system_graph(
        transition_closed_loop_system,
        state_initial_closed_loop_system,
        assumption.event_system,
        assumption.event_attacker_observable,
        assumption.event_vulnerable,
        assumption.event_supervisor_observable,
        assumption.event_supervisor_controllable,
    )
    closed_loop_graph.render("closed_loop_system_graph", format="png", cleanup=True)
    # 1.4 生成闭环语言
    language_closed_loop_system = ClosedLoopSystem.generate_language_closed_loop_system(
        transition_closed_loop_system,
        state_initial_closed_loop_system
    )
    print("闭环系统语言:", language_closed_loop_system)
    print("="*60)
    #2. ACAG系统
    
    #2.1 生成监督器不可观测可达集
    unobservable_reachable_supervisor = GenerateACAGFunctionTools.generate_unobserver_reach_supervisor(
        states_closed_loop_system,
        transition_closed_loop_system,
        assumption.event_supervisor_observable,
        event_unobservable_supervisor
        )
    #验证结果
    print("监督器不可观测可达集:")
    GenerateACAGFunctionTools.verify_unobservable_reach_results(unobservable_reachable_supervisor)
    print("="*60)
    #2.2 生成攻击者不可观测可达集
    unobservable_reachable_attacker = GenerateACAGFunctionTools.generate_unobserver_reach_attacker(
        assumption.state_initial_origin_ststem,
        assumption.transition_origin_system,
        assumption.event_attacker_observable,
        event_unobservable_attacker
    )
    #验证结果
    print("攻击者不可观测可达集:")
    GenerateACAGFunctionTools.verify_unobservable_reach_results(unobservable_reachable_attacker)
    print("="*60)
    #2.3 生成ACAG系统转移关系集合
    transition_ACAG_system = ACAGSystemCreater.generate_ACAG_transition(
                                 event_unobservable_attacker,
                                 assumption.event_vulnerable,
                                 assumption.event_alterable,
                                 event_unobservable_supervisor,
                                 transition_closed_loop_system,
                                 assumption.transition_origin_system,
                                 assumption.transition_supervisor,
                                 assumption.state_initial_origin_ststem,
                                 state_initial_closed_loop_system,
                                 assumption.state_initial_supervisor,
                                 unobservable_reachable_supervisor,
                                 unobservable_reachable_attacker

    )
    print("ACAG系统转移关系集合:", transition_ACAG_system)
    print("="*60)
    #3. 生成ACAG完整图
    #4. 生成AO-ACAG系统完整信息
    #5. 绘制AO-ACAG完整图
    #6. 生成pruned AO-ACAG完整信息
    #7. 绘制pruned AO-ACAG完整图
    #8. 生成攻击者策略