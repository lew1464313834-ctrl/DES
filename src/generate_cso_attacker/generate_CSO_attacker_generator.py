import sys
import graphviz
import re
import os
from collections import defaultdict

class CSO_Attacker_Strategy:
    sys.setrecursionlimit(10000)

    @staticmethod
    def generate_advanced_attacker_strategies(pruned_transitions, q0_tags, lable_ACAG_map, secret_states):
        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}

        def is_secret_node(tags):
            for tag in tags:
                orig = tag_to_state.get(tag)
                if orig and len(orig) >= 2 and len(orig[1]) > 0:
                    if orig[1].issubset(secret_states):
                        return True
            return False

        # 1. 建立正向和反向邻接表
        forward_adj = defaultdict(lambda: defaultdict(list))
        backward_adj = defaultdict(lambda: defaultdict(list))
        all_nodes = set()
        
        for (qa_info, t_sigma), next_qe in pruned_transitions.items():
            curr_qe, o_sigma = qa_info
            all_nodes.update([curr_qe, next_qe])
            forward_adj[curr_qe][next_qe].append((o_sigma, t_sigma))
            backward_adj[next_qe][curr_qe].append((o_sigma, t_sigma))

        # 2. SCC 路径提取器 (Tarjan 算法)
        def get_sccs(nodes, adj):
            visited_time = {}
            low_link = {}
            stack = []
            on_stack = set()
            timer = 0
            sccs = []

            def dfs_scc(u):
                nonlocal timer
                visited_time[u] = low_link[u] = timer
                timer += 1
                stack.append(u)
                on_stack.add(u)

                for v in adj.get(u, {}):
                    if v not in visited_time:
                        dfs_scc(v)
                        low_link[u] = min(low_link[u], low_link[v])
                    elif v in on_stack:
                        low_link[u] = min(low_link[u], visited_time[v])

                if low_link[u] == visited_time[u]:
                    component = []
                    while True:
                        node = stack.pop()
                        on_stack.remove(node)
                        component.append(node)
                        if node == u: break
                    sccs.append(component)

            for node in nodes:
                if node not in visited_time:
                    dfs_scc(node)
            return sccs

        # 识别非平凡 SCC (环路)
        sccs = get_sccs(all_nodes, forward_adj)
        node_to_scc_id = {}
        scc_strategies = {}
        scc_counter = 1

        for comp in sccs:
            # 一个节点且无自环则不是真正的环
            if len(comp) > 1 or (len(comp) == 1 and comp[0] in forward_adj.get(comp[0], {})):
                tn_label = f"T{scc_counter}"
                for n in comp:
                    node_to_scc_id[n] = tn_label
                
                # 提取环路内的一个代表性策略路径 [o(t)o(t)...]
                # 寻找从 comp[0] 回到 comp[0] 的最短路径
                start_node = comp[0]
                queue = [(start_node, "")]
                v_in_scc = {start_node}
                loop_str = ""
                
                found = False
                temp_q = [(start_node, "")]
                while temp_q:
                    curr, path = temp_q.pop(0)
                    for nxt, actions in forward_adj[curr].items():
                        if nxt in comp:
                            o, t = actions[0]
                            new_path = path + f"{o}({t})"
                            if nxt == start_node:
                                loop_str = new_path
                                found = True
                                break
                            if nxt not in v_in_scc:
                                v_in_scc.add(nxt)
                                temp_q.append((nxt, new_path))
                    if found: break
                scc_strategies[tn_label] = f"[{loop_str}]"
                scc_counter += 1

        # 3. 计算分母：总的死胡同节点数
        terminal_nodes = [n for n in all_nodes if n not in forward_adj or not forward_adj[n]]
        total_terminals = len(terminal_nodes) if terminal_nodes else 1

        # 4. 反向遍历提取策略（从秘密到 q0）
        secret_nodes = [n for n in all_nodes if is_secret_node(n)]
        raw_strategies = defaultdict(set) # path_str -> set(secret_nodes)

        def backtrack(curr, path_list, visited_in_path, found_tn):
            if curr == q0_tags:
                strategy_str = "".join(reversed(path_list))
                return {strategy_str}

            results = set()
            for prev, actions in backward_adj[curr].items():
                for o, t in actions:
                    step = f"{o}({t})"
                    
                    # 检查 Tn 标记逻辑
                    new_found_tn = found_tn
                    current_step = step
                    if prev in node_to_scc_id:
                        tn = node_to_scc_id[prev]
                        if tn not in found_tn:
                            current_step = tn
                            new_found_tn = found_tn | {tn}
                        else:
                            # 已经在当前路径的环里了，跳过避免死循环
                            continue

                    if prev not in visited_in_path:
                        res_paths = backtrack(prev, path_list + [current_step], 
                                              visited_in_path | {curr}, new_found_tn)
                        results.update(res_paths)
            return results

        for snode in secret_nodes:
            paths = backtrack(snode, [], set(), set())
            for p in paths:
                raw_strategies[p].add(snode)

        # 5. 整合与计算概率
        final_dict = {}
        for path, reached_secrets in raw_strategies.items():
            # 将 Tn 替换为具体的环路内容 [o(t)...]
            formatted_path = path
            for tn, content in scc_strategies.items():
                formatted_path = formatted_path.replace(tn, content)
            
            # 概率 = 该策略到达的秘密状态数 / 总死胡同数
            prob = (len(reached_secrets) / total_terminals) * 100
            final_dict[formatted_path] = f"{prob:.2f}%"

        return final_dict
    @staticmethod
    def draw_attacker_graph(strategy_dict, filename):
        """
        为字典中的每一个攻击者策略生成一个独立的 SVG 文件。
        :param strategy_dict: 攻击策略字典 {路径: 概率}
        :param filename: 输出路径及文件前缀 (例如: "resources/cso-attacker/attacker_dfa")
        """
        # 1. 解析路径：提取目录和基本文件名
        output_dir = os.path.dirname(filename)
        base_name = os.path.basename(filename)

        # 如果目录不存在则创建
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # 正则表达式：匹配 o(t) 格式 或 [o(t)...] 环路格式
        token_pattern = re.compile(r'(\[[^\]]+\]|[a-zA-Z0-9_]+\([^)]*\))')

        # 按概率排序（从高到低），取前 5
        top_strategies = sorted(strategy_dict.items(), key=lambda x: float(x[1].strip('%')), reverse=True)[:5]

        for i, (path_str, prob) in enumerate(top_strategies, 1):
            # 生成带编号的文件名 (例如: attacker_dfa_1)
            current_file_prefix = f"{base_name}_{i}"
            dot = graphviz.Digraph(name=current_file_prefix, format='svg')
            
            # 图形全局属性
            dot.attr(rankdir='LR', size='10,6')
            dot.attr('node', shape='circle', fontname='Arial', fontsize='10')
            dot.attr('edge', fontname='Arial', fontsize='9')
            dot.attr(label=f"Attacker {i} | Success Prob: {prob}", labelloc='t', fontsize='12')

            # 初始节点
            dot.node('START', '', shape='point')
            dot.node('q0', 'q0', style='filled', fillcolor='#eeeeee')
            dot.edge('START', 'q0')

            # 解析动作单元
            tokens = token_pattern.findall(path_str)
            current_node = "q0"

            for idx, token in enumerate(tokens):
                is_loop = token.startswith('[') and token.endswith(']')
                is_last = (idx == len(tokens) - 1)
                
                if is_loop:
                    # 环路处理
                    loop_label = token.strip('[]')
                    dot.edge(current_node, current_node, label=loop_label, color='blue', style='dashed')
                else:
                    # 正常节点
                    next_node_id = f"s{idx+1}"
                    if is_last:
                        dot.node(next_node_id, "SECRET", shape='doublecircle', fillcolor='#d4edda', style='filled')
                    else:
                        dot.node(next_node_id, f"q{idx+1}")
                    
                    dot.edge(current_node, next_node_id, label=token)
                    current_node = next_node_id

            # 保存文件
            save_path = os.path.join(output_dir, current_file_prefix) if output_dir else current_file_prefix
            dot.render(save_path, cleanup=True)
            print(f"Generated: {save_path}.svg")