import re

from v6.structs import SharedFunctionInfo
from v6.disasm import disassemble_bytecode
from common.enums import ScopeInfoFlagsScope


def format_scope_info(scope_info, indent="  "):
    lines = []
    if scope_info is None:
        return lines

    flags = scope_info.flags
    scope_type = flags.scope.name if flags.scope is not None else "UNKNOWN"
    lang = flags.lang_mode.name if flags.lang_mode is not None else "?"

    lines.append("%sScope: %s (%s)" % (indent, scope_type, lang))

    if scope_info.params:
        lines.append("%sParameters (%d): %s" % (indent, len(scope_info.params),
                                                  ", ".join(scope_info.params)))

    if scope_info.stack_locals:
        lines.append("%sStack locals (%d, first_slot=%d): %s" % (
            indent, len(scope_info.stack_locals),
            scope_info.stack_locals_first_slot,
            ", ".join(scope_info.stack_locals)))

    if scope_info.context_locals:
        lines.append("%sContext locals (%d): %s" % (
            indent, len(scope_info.context_locals),
            ", ".join(scope_info.context_locals)))

    return lines


def format_constant_pool(cp, indent="  "):
    lines = []
    if cp is None:
        return lines

    lines.append("%sConstant Pool (%d entries):" % (indent, cp.count))
    for i, item in enumerate(cp.items):
        if isinstance(item, str):
            lines.append('%s  [%d] "%s"' % (indent, i, item[:80]))
        elif isinstance(item, float):
            lines.append("%s  [%d] %s" % (indent, i, repr(item)))
        elif isinstance(item, int):
            lines.append("%s  [%d] Smi(%d)" % (indent, i, item))
        elif hasattr(item, "name"):
            lines.append("%s  [%d] %s" % (indent, i, item.name))
        else:
            lines.append("%s  [%d] %s" % (indent, i, type(item).__name__))

    return lines


def format_handler_table(ht, indent="  "):
    lines = []
    if ht is None or not ht.entries:
        return lines

    lines.append("%sHandler Table (%d entries):" % (indent, len(ht.entries)))
    for i, entry in enumerate(ht.entries):
        pred_names = ["CAUGHT", "UNCAUGHT", "PROMISE", "DESUGARING", "ASYNC_AWAIT", "??", "??", "??"]
        pred_name = pred_names[entry.prediction] if entry.prediction < len(pred_names) else "?"
        lines.append("%s  [%d] range=[%d, %d) handler=@%04X prediction=%s data=%d" % (
            indent, i, entry.start, entry.end, entry.handler_offset,
            pred_name, entry.data))

    return lines


def format_bytecode(bytecode_data, indent="  "):
    lines = []
    if bytecode_data is None:
        return lines

    instructions = disassemble_bytecode(
        bytecode_data.bytecode,
        bytecode_data.constant_pool,
        bytecode_data.handler_table,
    )

    for offset, mnemonic, operands, raw_bytes, comment in instructions:
        hex_bytes = " ".join("%02X" % b for b in raw_bytes)
        line = "%s%04X: %-24s %-30s %s" % (indent, offset, hex_bytes, mnemonic + " " + operands if operands else mnemonic, comment)
        lines.append(line.rstrip())

    return lines


def format_function(sfi, verbose=False):
    lines = []
    lines.append("=" * 70)
    lines.append("Function: %s (id=%d)" % (sfi.name, sfi.function_literal_id))
    lines.append("-" * 70)

    lines.append("  Formal parameters: %d" % sfi.formal_parameter_count)
    lines.append("  Function length: %d" % sfi.function_length)
    lines.append("  Start position: %d" % (sfi.start_position_and_type >> 2))
    lines.append("  End position: %d" % sfi.end_position)

    if sfi.bytecode:
        lines.append("  Bytecode length: %d" % sfi.bytecode.length)
        lines.append("  Frame size: %d" % sfi.bytecode.frame_size)

    if sfi.scope_info:
        lines.extend(format_scope_info(sfi.scope_info))

    if verbose and sfi.bytecode and sfi.bytecode.constant_pool:
        lines.append("")
        lines.extend(format_constant_pool(sfi.bytecode.constant_pool))

    if verbose and sfi.bytecode and sfi.bytecode.handler_table:
        lines.append("")
        lines.extend(format_handler_table(sfi.bytecode.handler_table))

    if sfi.bytecode:
        lines.append("")
        lines.append("  Bytecode:")
        lines.extend(format_bytecode(sfi.bytecode, indent="    "))

    lines.append("")
    return "\n".join(lines)


def format_output(version, bitness, functions, verbose=False):
    lines = []
    lines.append("V8 JSC Decompiler Output")
    lines.append("=" * 70)
    lines.append("V8 Version: %s" % version)
    lines.append("Architecture: %s" % ("32-bit" if bitness else "64-bit"))
    lines.append("Functions found: %d" % len(functions))
    lines.append("")

    for sfi in functions:
        lines.append(format_function(sfi, verbose=verbose))

    return "\n".join(lines)


def _is_wrapper_function(sfi):
    """Check if a function is a V8/Node.js internal wrapper."""
    # Script-level wrapper (id=0, SCRIPT_SCOPE)
    if sfi.scope_info and sfi.scope_info.flags.scope == ScopeInfoFlagsScope.SCRIPT_SCOPE:
        return True
    # Node.js CommonJS module wrapper
    if sfi.scope_info and list(sfi.scope_info.params) == [
            "exports", "require", "module", "__filename", "__dirname"]:
        return True
    return False


def format_js_output(version, bitness, functions, filename=""):
    from reconstructor import reconstruct_js

    user_functions = [sfi for sfi in functions if not _is_wrapper_function(sfi)]

    lines = []
    lines.append("// V8 Version: %s (%s)" % (version, "32-bit" if bitness else "64-bit"))
    if filename:
        lines.append("// Decompiled from: %s" % filename)
    lines.append("// Functions: %d" % len(user_functions))
    lines.append("")

    for sfi in user_functions:
        # Build function signature
        params = []
        if sfi.scope_info:
            params = list(sfi.scope_info.params)
        param_str = ", ".join(params)

        lines.append("function %s(%s) {" % (sfi.name, param_str))

        # Declare stack locals
        if sfi.scope_info and sfi.scope_info.stack_locals:
            locals_list = []
            for l in sfi.scope_info.stack_locals:
                if l and l != "empty_string" and l not in params:
                    # Sanitize names with dots or other invalid chars
                    clean = l.replace(".", "_").replace(" ", "_")
                    if clean and clean not in locals_list:
                        locals_list.append(clean)
            if locals_list:
                lines.append("    var %s;" % ", ".join(locals_list))

        body = reconstruct_js(sfi)
        if body.strip():
            lines.append(body)
        lines.append("}")
        lines.append("")

    return "\n".join(lines)


def format_json_output(version, bitness, functions):
    import json

    result = {
        "version": version,
        "architecture": "32-bit" if bitness else "64-bit",
        "functions": [],
    }

    for sfi in functions:
        func = {
            "name": sfi.name,
            "id": sfi.function_literal_id,
            "formal_parameters": sfi.formal_parameter_count,
            "function_length": sfi.function_length,
            "start_position": sfi.start_position_and_type >> 2,
            "end_position": sfi.end_position,
        }

        if sfi.bytecode:
            func["bytecode_length"] = sfi.bytecode.length
            func["frame_size"] = sfi.bytecode.frame_size

            if sfi.bytecode.constant_pool:
                cp_items = []
                for item in sfi.bytecode.constant_pool.items:
                    if isinstance(item, str):
                        cp_items.append({"type": "string", "value": item})
                    elif isinstance(item, float):
                        cp_items.append({"type": "number", "value": item})
                    elif isinstance(item, int):
                        cp_items.append({"type": "smi", "value": item})
                    elif hasattr(item, "name"):
                        cp_items.append({"type": "object", "value": str(item.name)})
                    else:
                        cp_items.append({"type": "unknown", "value": str(type(item).__name__)})
                func["constant_pool"] = cp_items

            instructions = disassemble_bytecode(
                sfi.bytecode.bytecode,
                sfi.bytecode.constant_pool,
                sfi.bytecode.handler_table,
            )
            func["bytecode"] = []
            for offset, mnemonic, operands, raw_bytes, comment in instructions:
                func["bytecode"].append({
                    "offset": offset,
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "hex": " ".join("%02X" % b for b in raw_bytes),
                })

        if sfi.scope_info:
            func["scope"] = {
                "type": sfi.scope_info.flags.scope.name if sfi.scope_info.flags.scope else "UNKNOWN",
                "params": sfi.scope_info.params,
                "stack_locals": sfi.scope_info.stack_locals,
                "context_locals": sfi.scope_info.context_locals,
            }

        result["functions"].append(func)

    return json.dumps(result, indent=2)
