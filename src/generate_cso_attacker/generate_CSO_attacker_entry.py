from .utils.logger import get_logger
from .system_DFA_basic import ClosedLoopSystem
from .generate_ACAG_helper import GenerateACAGFunctionTools
from .generate_ACAG_generator import ACAGSystemCreater
from .generate_AO_ACAG_generator import AOACAGSystemCreater
from .generate_pruned_AO_ACAG_generator import PrunedAOACAGSystemCreater
from .correspond_graph_simplyfier import GraphSimplyfier
from .system_assumption import assumption_one

assumption = assumption_one
class CSO_Attacker_Generator:
    @staticmethod
    def generate_cso_attacker():
        app_logger = get_logger("cso_atk", "logs")
        
        #1.闭环系统
        #生成攻击者和监督器的不可观测事件集
        event_unobservable_supervisor=ClosedLoopSystem.generate_unobservable_events(
            assumption.event_system,
            assumption.event_supervisor_observable
        )
        app_logger.info(f'监督器不可观测事件: {event_unobservable_supervisor}')
        app_logger.info("="*60)
        event_unobservable_attacker=ClosedLoopSystem.generate_unobservable_events(
            assumption.event_system,
            assumption.event_attacker_observable
        )
        app_logger.info(f'攻击者不可观测事件: {event_unobservable_attacker}')
        app_logger.info("="*60)
        #1.1 生成闭环系统状态集合
        states_closed_loop_system=ClosedLoopSystem.generate_states_closed_loop_system(assumption.state_oringin_system,
                                                                assumption.state_initial_origin_ststem,
                                                                assumption.state_initial_supervisor,
                                                                assumption.event_system,
                                                                assumption.transition_origin_system,
                                                                assumption.transition_supervisor
                                                                )
        app_logger.info(f'闭环系统状态集合: {states_closed_loop_system}')
        app_logger.info("="*60)
        #1.2 生成闭环转换关系
        transition_closed_loop_system=ClosedLoopSystem.generate_transition_closed_loop_system(assumption.state_oringin_system,
                                                                assumption.state_initial_origin_ststem,
                                                                assumption.state_initial_supervisor,
                                                                assumption.event_system,
                                                                assumption.transition_origin_system,
                                                                assumption.transition_supervisor
                                                                )
        app_logger.info(f'闭环转换关系:{transition_closed_loop_system}')
        app_logger.info("="*60)
        # 1.3 闭环系统初始状态
        state_initial_closed_loop_system = ClosedLoopSystem.generate_states_initial_closed_loop_system(
            assumption.state_initial_supervisor,
            assumption.state_initial_origin_ststem,
            states_closed_loop_system
        )
        app_logger.info(f'初始状态:{state_initial_closed_loop_system}')
        app_logger.info("="*60)
        # 1.4 生成闭环系统图
        closed_loop_graph = ClosedLoopSystem.generate_closed_loop_system_graph(
            transition_closed_loop_system, 
            state_initial_closed_loop_system,
            assumption.event_system,
            assumption.event_attacker_observable,
            assumption.event_vulnerable,
            assumption.event_supervisor_observable,
            assumption.event_supervisor_controllable,
            assumption.state_system_secret,
            file_name="resources/cso-attacker/closed_loop_graph"
        )
        # 额外输出PDF格式
        closed_loop_graph.format = 'pdf'
        closed_loop_graph.render("resources/cso-attacker/closed_loop_graph_pdf", cleanup=True)  # 输出PDF格式
        # 1.5 生成闭环语言
        language_closed_loop_system = ClosedLoopSystem.generate_language_closed_loop_system(
            transition_closed_loop_system,
            state_initial_closed_loop_system
        )
        app_logger.info(f'闭环系统语言:{language_closed_loop_system}')
        app_logger.info("="*60)
        #2. ACAG系统
        
        #2.1 生成监督器不可观测可达集
        unobservable_reachable_supervisor = GenerateACAGFunctionTools.generate_unobserver_reach_supervisor(
            transition_closed_loop_system,
            assumption.event_supervisor_observable,
            event_unobservable_supervisor
            )
        #验证结果
        print("生成监督器不可观测可达集")
        app_logger.info(f'监督器不可观测可达集:{unobservable_reachable_supervisor}')
        app_logger.info("="*60)
        #验证标签结果集
        labled_unobservable_reachable_supervisor=GenerateACAGFunctionTools.label_unobserver_reach_supervisor(unobservable_reachable_supervisor)
        print("验证标签结果集")
        app_logger.info(f'标签结果集:{labled_unobservable_reachable_supervisor}')
        #2.2 生成攻击者不可观测可达集
        unobservable_reachable_attacker = GenerateACAGFunctionTools.generate_unobserver_reach_attacker(
            assumption.state_initial_origin_ststem,
            assumption.transition_origin_system,
            assumption.event_attacker_observable,
            assumption.state_supervisor,
            assumption.transition_supervisor,
            event_unobservable_attacker
        )
        print("生成攻击者不可观测可达集")
        app_logger.info(f'攻击者不可观测可达集:{unobservable_reachable_attacker}')
        app_logger.info("="*60)
        #验证标签结果集
        labled_unobservable_reachable_attacker=GenerateACAGFunctionTools.label_unobserver_reach_attacker(unobservable_reachable_attacker,assumption.state_supervisor)
        app_logger.info(f'标签结果集:{labled_unobservable_reachable_attacker}')
        #2.3 生成ACAG系统转移关系集合
        transition_ACAG_system,initial_env_state = ACAGSystemCreater.generate_ACAG_transition(
            event_unobservable_attacker,
            assumption.event_vulnerable,
            assumption.event_alterable,
            event_unobservable_supervisor,
            transition_closed_loop_system,
            assumption.transition_origin_system,      # 物理系统转移字典
            assumption.transition_supervisor,         # 监督器实现字典
            assumption.state_initial_origin_ststem,
            state_initial_closed_loop_system,
            assumption.state_initial_supervisor,
            unobservable_reachable_supervisor,
            unobservable_reachable_attacker,
            assumption.state_system_secret,                # 秘密状态集
        )
        #验证结果
        app_logger.info("ACAG系统转移关系集合:")
        for state,next_state in transition_ACAG_system.items():
            app_logger.info(f'{state} -> {next_state}')
        app_logger.info("="*60)
        print("记录ACAG系统转移关系集合")
        #3. 生成ACAG完整图
        graph_ACAG_system,lable_ACAG_map = ACAGSystemCreater.draw_ACAG_graph(
            transition_ACAG_system,
            initial_env_state,
            assumption.state_system_secret,
            labled_unobservable_reachable_supervisor,
            labled_unobservable_reachable_attacker,
            filename='resources/cso-attacker/ACAG'
        )
        print("生成ACAG完整图")
        graph_ACAG_system.format = 'pdf'
        graph_ACAG_system.render("resources/cso-attacker/ACAG_pdf", cleanup=True)
        #查看ACAG标签关系
        app_logger.info("ACAG标签关系:")
        for key,value in lable_ACAG_map.items():
            app_logger.info(f'{key} -> {value}')
        app_logger.info("="*60)
        #4. 生成AO-ACAG系统完整信息
        #4.1 生成AO-ACAG系统转换关系集合
        all_transition_AO_ACAG_system,intial_AO_env_state = AOACAGSystemCreater.generate_AO_ACAG_transition(
            transition_ACAG_system,
            initial_env_state,
            lable_ACAG_map,
            event_unobservable_attacker
        )
        print("生成AO-ACAG系统转换关系集合")
        app_logger.info("AO-ACAG系统转换关系集合:")
        for state,next_state in all_transition_AO_ACAG_system.items():
            app_logger.info(f'{state} -> {next_state}')
        app_logger.info("="*60)
        #5. 绘制AO-ACAG完整图
        graph_AO_ACAG_system,lable_AOACAG_map=AOACAGSystemCreater.draw_AO_ACAG_graph(
            all_transition_AO_ACAG_system,
            intial_AO_env_state,
            lable_ACAG_map,
            assumption.state_system_secret,
            filename='resources/cso-attacker/AO-ACAG'
        )
        print("绘制AO-ACAG完整图")
        graph_AO_ACAG_system.format='pdf'
        graph_AO_ACAG_system.render("resources/cso-attacker/AO-ACAG_pdf", cleanup=True)
        #6. 生成pruned AO-ACAG完整信息
        all_transition_pruned_AO_ACAG_system,intial_pruned_AO_env_state=PrunedAOACAGSystemCreater.generate_pruned_AO_ACAG_transition(
            all_transition_AO_ACAG_system,
            intial_AO_env_state
        )
        print("生成pruned AO-ACAG系统转换关系集合")
        app_logger.info("pruned AO-ACAG系统转换关系集合:")
        for state,next_state in all_transition_pruned_AO_ACAG_system.items():
            app_logger.info(f'{state} -> {next_state}')
        app_logger.info("="*60)
        #7. 绘制pruned AO-ACAG完整图
        graph_pruned_AO_ACAG_system=PrunedAOACAGSystemCreater.draw_pruned_AO_ACAG_graph(
            all_transition_pruned_AO_ACAG_system,
            intial_pruned_AO_env_state,
            lable_ACAG_map,
            assumption.state_system_secret,
            lable_AOACAG_map,
            filename='resources/cso-attacker/pruned-AO-ACAG'
        )
        print("绘制pruned AO-ACAG完整图")
        graph_pruned_AO_ACAG_system.format='pdf'
        graph_pruned_AO_ACAG_system.render("resources/cso-attacker/pruned-AO-ACAG_pdf", cleanup=True)
        #8. 生成简略的可放在论文中的图
        #8.1 生成简略的ACAG图
        GraphSimplyfier.draw_paper_simplified_ACAG(
            transition_ACAG_system,
            initial_env_state,
            assumption.state_system_secret,
            labled_unobservable_reachable_supervisor,
            labled_unobservable_reachable_attacker,
            filename="resources/cso-attacker/simplified_ACAG"
        )
        print("生成简略的ACAG图")