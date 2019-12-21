import ida_idaapi
import ida_kernwin
import ida_hexrays


# Define callbacks which are the actions I actually
# want to perform


# Define the action_handler_t object that fires the
# callback function when each action is activated



# Return values for update (from the SDK):
# AST_ENABLE_ALWAYS     // enable action and do not call action_handler_t::update() anymore
# AST_ENABLE_FOR_IDB    // enable action for the current idb. Call action_handler_t::update() when a database is opened/closed
# AST_ENABLE_FOR_FORM   // enable action for the current form. Call action_handler_t::update() when a form gets/loses focus
# AST_ENABLE            // enable action - call action_handler_t::update() when anything changes
# AST_DISABLE_ALWAYS    // disable action and do not call action_handler_t::action() anymore
# AST_DISABLE_FOR_IDB   // analog of ::AST_ENABLE_FOR_IDB
# AST_DISABLE_FOR_FORM  // analog of ::AST_ENABLE_FOR_FORM
# AST_DISABLE           // analog of ::AST_ENABLE

DEBUG = True
def debug(msg):
    global DEBUG
    if DEBUG:
        print('[*] DEBUG: %s' % msg)

class Action(ida_kernwin.action_handler_t):
    hotkey = None
    description = "Just an abstract class"

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # @property
    # def name():
    #     return "IDABuddy" + type(self).__name__

    def activate(self, ctx):
        raise NotImplementedError

    def update(self, ctx):
        raise NotImplementedError


class MakeItConst(Action):
    hotkey = 'Shift+C'
    description = 'Make it const'
    name = 'IDABuddy:MakeItConst'

    def __init__(self):
        super(MakeItConst, self).__init__()

    def activate(self, ctx):
        hx_view = ida_hexrays.get_widget_vdui(ctx.widget)
        # if self.check(ctx.cfunc,

    def update(self, ctx):
        debug('ctx.widget_type == %d' % ctx.widget_type)
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:

            return ida_kernwin.AST_ENABLE_FOR_FORM
        # ida_kernwin.detach_action_from_popup(ctx.widget, self.name)
        return ida_kernwin.AST_DISABLE_FOR_FORM

    @staticmethod
    def check(cfunc, ctree_item):
        lvar = ctree_item.get_lvar()
        if lvar is not None:
            tinfo = lvar.type()
            # tinfo.clr_const()
            debug(tinfo.is_ptr())


        if ctree_item.citype != ida_kernwin.VDI_EXPR:
            return False


        return False



class BuddyHooks(ida_hexrays.Hexrays_Hooks):
    def _shorten(self, cfunc):
        raw = str(cfunc)
        if len(raw) > 20:
            raw = raw[0:20] + "[...snipped...]"
        return raw

    def _format_lvar(self, v):
        parts = []
        if v:
            if v.name:
                parts.append("name=%s" % v.name)
            if v.cmt:
                parts.append("cmt=%s" % v.cmt)
            parts.append("width=%s" % v.width)
            parts.append("defblk=%s" % v.defblk)
            parts.append("divisor=%s" % v.divisor)
        return "{%s}" % ", ".join(parts)

    def _log(self, msg):
        print("### %s" % msg)
        return 0


    def create_hint(self, vu):
        return self._log("create_hint: vu=%s: " % vu)

    def text_ready(self, vu):
        return self._log("text_ready: vu=%s" % vu)

    def populating_popup(self, widget, popup, vu):
        print '[*] DEBUG: vu.item.citype = %d' % vu.item.citype
        if vu.item.citype != ida_hexrays.VDI_EXPR:
            return 0

        lvar = vu.item.get_lvar()

        ida_kernwin.attach_action_to_popup(widget, popup, MakeItConst.name, None)
        return self._log("populating_popup: widget=%s, popup=%s, vu=%s" % (widget, popup, vu))


class Action(ida_kernwin.action_handler_t):

    def __init__(self):
        super(Action, self).__init__(self)
            
    def activate(self, ctx):
        raise NotImplementedError

    def check(self, hx_view):
        raise NotImplementedError

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def hx_actions_dispatcher(*args):
    hexrays_event = args[0]
    print hexrays_event


# Define a method to register all the actions when
# the plugin is initialized


# Define the plugin class itself which is returned by
# the PLUGIN_ENTRY method that scriptable plugins use
# to be recognized within IDA
def register(action, *args):
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            action.name,
            action.description,
            action(*args),
            action.hotkey
        )
    )


def unregister(action):
    ida_kernwin.unregister_action(action.name)


class IDABuddy(ida_idaapi.plugin_t):

    # Use the HIDE flag to avoid the entry in 
    # Edit/Plugins since this plugin's run() 
    # method has no functionality...it's all 
    # in the actions.

    flags = ida_idaapi.PLUGIN_HIDE
    comment = 'IDABuddy plugin'
    help = 'No help - this is just a IDABuddy'
    wanted_name = 'IDABuddy'
    wanted_hotkey = ''

    def init(self):
        print('IDABuddy init')

        if not ida_hexrays.init_hexrays_plugin():
            db_error('Failed to initialize Hex-Rays SDK')
            return ida_idaapi.PLUGIN_SKIP
        
        # actions registration block
        register(MakeItConst)

        self.hx_hook = BuddyHooks()
        self.hx_hook.hook()

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.hx_hook.unhook()
        unregister(MakeItConst)
        ida_hexrays.term_hexrays_plugin()

# The PLUGIN_ENTRY method is what IDA calls when
# scriptable plugins are loaded. It needs to
# return a plugin of type ida_idaapi.plugin_t

def PLUGIN_ENTRY():
    pass
'''
    try:
        return IDABuddy()
    
    except Exception, err:
        import traceback
        db_error('%s\n%s' % str((err), traceback.format_exc()))
        raise
'''