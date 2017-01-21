# Summary:
#   Given a global name, find all xrefs which are contained in an exported function.
#
# How to use:
#   1.  click a global name
#   2.  run the script
#
# Sample output for ntoskrnl.SeDebugPrivilege:
#
#   ================================================================================
#   Dumping exported xrefs for:  SeDebugPrivilege  0x1405460b0
#   ================================================================================
#   0x1403d1781  NtSetInformationThread + 0x88011
#   0x1403d43a8  NtSetInformationProcess + 0x65E0C
#   0x1403d4823  NtSetInformationProcess + 0x66287


import idaapi
import idautils


def idahex(address):
    return hex(address).rstrip("L")


def main():
    ea = idaapi.get_screen_ea()

    # export entry = tuple(index, ordinal, address, name)
    exports = {export[2]:export for export in idautils.Entries()}

    # list of tuple(xref_address, export_name, xref_offset)
    exported_xrefs = []

    xrefs = [x.frm for x in idautils.XrefsTo(ea)]
    for xref in xrefs:
        func = idaapi.get_func(xref)
        if func and func.startEA in exports:
            exported_xrefs.append((xref, exports[func.startEA][3], xref - func.startEA))

    if exported_xrefs:
        delim = "=" * 80
        print delim
        print "Dumping exported xrefs for:  %s  %s" % (idaapi.get_name(ea, ea), idahex(ea))
        print delim
        for exported_xref in exported_xrefs:
            print "%s  %s + 0x%X" % (idahex(exported_xref[0]), exported_xref[1], exported_xref[2])
    else:
        print "%s  %shas no exported xrefs." % (idahex(ea), idaapi.get_name(ea, ea) or "")


if __name__ == '__main__':
    main()