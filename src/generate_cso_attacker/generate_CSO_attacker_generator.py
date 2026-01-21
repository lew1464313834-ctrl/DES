import sys

class CSO_Attacker_Strategy:
    sys.setrecursionlimit(10000)

    @staticmethod
    def generate_advanced_attacker_strategies(pruned_transitions, 
                                              q0_tags, 
                                              lable_ACAG_map, 
                                              secret_states):
        """
        提取包含环路具体路径的攻击策略，并严格计算成功率。
        过滤掉无法发现秘密的死胡同路径。
        """
        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}

        def is_secret_node(tags):
            """判定节点是否包含秘密状态"""
            for tag in tags:
                orig = tag_to_state.get(tag)
                # 状态结构 (xi_S, xi_A, z, x), xi_A 是 index 1
                if orig and len(orig) >= 2 and len(orig[1]) > 0:
                    if orig[1].issubset(secret_states):
                        return True
            return False

        # 1. 预处理图结构
        # adj[curr_qe] = { next_qe: [(o, t), ...] }
        adj = {}
        for (qa_info, t_sigma), next_qe in pruned_transitions.items():
            curr_qe, o_sigma = qa_info
            if curr_qe not in adj: adj[curr_qe] = {}
            if next_qe not in adj[curr_qe]: adj[curr_qe][next_qe] = []
            adj[curr_qe][next_qe].append((o_sigma, t_sigma))

        strategy_dict = {}

        def find_all_paths(curr_node, path_str, visited_nodes, secret_count):
            """
            递归遍历所有可能路径。
            visited_nodes: 用于防止在环路中无限递归，每个节点在一条路径中最多出现两次以展示环路。
            """
            # 标记当前节点
            new_visited = visited_nodes.copy()
            new_visited[curr_node] = new_visited.get(curr_node, 0) + 1
            
            # 计算当前节点的秘密属性
            current_is_secret = is_secret_node(curr_node)
            new_secret_count = secret_count + (1 if current_is_secret else 0)
            
            # 如果没有出边，说明到达了终端节点
            if curr_node not in adj or not adj[curr_node]:
                # 核心逻辑：只有路径中至少包含一个秘密状态时，才认为该策略有效
                if new_secret_count > 0:
                    total_nodes = sum(new_visited.values())
                    prob = (new_secret_count / total_nodes) * 100
                    strategy_dict[path_str] = f"{prob:.2f}%"
                return

            # 遍历所有可能的下一跳
            for next_node, actions in adj[curr_node].items():
                # 环路处理：如果一个节点在当前路径已经出现了2次，则停止深入（视为已展示过环路行为）
                if new_visited.get(next_node, 0) >= 2:
                    # 到此为止，计算概率并记录
                    if new_secret_count > 0:
                        total_nodes = sum(new_visited.values())
                        prob = (new_secret_count / total_nodes) * 100
                        # 加上省略号表示环路继续
                        strategy_dict[path_str + "..."] = f"{prob:.2f}%"
                    continue

                for (o, t) in actions:
                    step = f"{o}({t})"
                    find_all_paths(next_node, path_str + step, new_visited, new_secret_count)

        # 2. 从初始节点开始搜索
        find_all_paths(q0_tags, "", {}, 0)

        # 3. 结果精简：如果 A 路径是 B 路径的前缀且概率相同，保留长的（可选）
        return strategy_dict