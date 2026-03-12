import gi
import sys
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('Vte', '3.91')
from gi.repository import Adw, Gtk, Vte, GLib

class TestWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.term = Vte.Terminal()
        self.term.set_vexpand(True)
        self.term.set_hexpand(True)
        self.set_content(self.term)

        self.term.feed(b"Hello from VTE feed!\r\nType something: ")
        self.term.connect("commit", self.on_commit)

    def on_commit(self, term, text, size):
        print(f"Typed: {repr(text)}")
        term.feed(text.encode('utf-8')) # local echo

class App(Adw.Application):
    def do_activate(self):
        win = TestWindow(application=self)
        win.present()

if __name__ == '__main__':
    App().run(sys.argv)
