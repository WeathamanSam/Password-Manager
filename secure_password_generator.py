import math
import random
import re
import string
from tkinter import *
from tkinter import BooleanVar
from tkinter import messagebox
from tkinter import ttk

class RandomPasswordGenerator:
    
    def __init__(self, root):
        
        # Sets up Main GUI Aspects
        root.title("Secure Password Generator")
        root.geometry("450x200")
        mainframe = ttk.Frame(root, padding="3 3 12 12")
        mainframe.grid(column=0, row=0)
        root.grid_columnconfigure(0, weight=1)
        
        # Password length and character set options
        self.password_length_var = IntVar(value=16)
        self.uppercase_var = BooleanVar(value=True)
        self.lowercase_var = BooleanVar(value=True)
        self.digits_var = BooleanVar(value=True)
        self.symbols_var = BooleanVar(value=True)
        self.exclude_ambiguous_var = BooleanVar(value=False)
        self.password_generated_var = BooleanVar(value=False)
        
        # Creates boundary buffers
        self.buffer_label_east = ttk.Label(mainframe, text="\n")
        self.buffer_label_west = ttk.Label(mainframe, text="\n")
        
        # Grid location of boundary buffers
        self.buffer_label_east.grid(column=9, row=0, rowspan=6, padx=5)
        self.buffer_label_west.grid(column=0, row=0, rowspan=6, padx=5)
        
        # Creates "Password Length" label and slider
        self.password_length_label = ttk.Label(mainframe, text="Password Length:")
        self.password_length_slider = ttk.Scale(mainframe, from_=12, to=24, orient=HORIZONTAL, variable=self.password_length_var)
        self.slider_label_min = ttk.Label(mainframe, text="12")
        self.slider_label_16 = ttk.Label(mainframe, text="16 ")
        self.slider_label_20 = ttk.Label(mainframe, text=" 20")
        self.slider_label_max = ttk.Label(mainframe, text="24")
        
        # Grid location of "Password Length" label and entry box
        self.password_length_label.grid(column=1, row=1, columnspan=4, sticky="W", padx=20)
        self.password_length_slider.grid(column=1, row=2, columnspan=4, sticky="ew")
        self.slider_label_min.grid(column=1, row=3, sticky="W")
        self.slider_label_16.grid(column=2, row=3)
        self.slider_label_20.grid(column=3, row=3)
        self.slider_label_max.grid(column=4, row=3, sticky="E")
        
        # Creates a horizontal barrier between sections
        self.horizontal_separator1 = ttk.Label(mainframe, text="")
        self.horizontal_separator1.grid(column=5, row=1, rowspan=3, padx=25)
        self.horizontal_separator2 = ttk.Label(mainframe, text="")
        self.horizontal_separator2.grid(column=8, row=1, rowspan=3, padx=25)
        
        # Creates a vertical barrier between sections
        self.vertical_separator1 = ttk.Label(mainframe, text="")
        self.vertical_separator1.grid(column=1, row=4, columnspan=7, pady=20)
        
        # Creates checkbuttons for password character options
        self.password_character_options_label = ttk.Label(mainframe, text="Character Options:")
        self.uppercase_checkbutton = ttk.Checkbutton(mainframe, text="Uppercase", variable=self.uppercase_var)
        self.lowercase_checkbutton = ttk.Checkbutton(mainframe, text="Lowercase", variable=self.lowercase_var)
        self.digits_checkbutton = ttk.Checkbutton(mainframe, text="Digits", variable=self.digits_var)
        self.symbols_checkbutton = ttk.Checkbutton(mainframe, text="Symbols", variable=self.symbols_var)
        
        # Grid location of character checkbuttons
        self.password_character_options_label.grid(column=6, row=1, columnspan=2)
        self.uppercase_checkbutton.grid(column=6, row=2, sticky="W")
        self.lowercase_checkbutton.grid(column=7, row=2, sticky="W")
        self.digits_checkbutton.grid(column=6, row=3, sticky="W")
        self.symbols_checkbutton.grid(column=7, row=3, sticky="W")
        
        # Creates textbox where passwords will be generated and displayed
        self.password_entry = ttk.Entry(mainframe, width=20)
        self.password_entry.grid(column=6, row=4, columnspan=2)
        
        # Creates button for passwords allowing the user to generate, show, copy, and display strength
        self.generate_password_button = ttk.Button(mainframe, text="Generate", command=self.generate_password)
        self.show_hide_text = StringVar(value="Show")
        self.show_button = ttk.Button(mainframe, textvariable=self.show_hide_text, command=self.toggle_show_password)
        self.copy_button = ttk.Button(mainframe, text="Copy", command=self.copy_password)
        self.strength_label = ttk.Label(mainframe, text="\nPassword Strength:")
        
        # Grid location of generate and show boxes
        self.generate_password_button.grid(column=6, row=5, columnspan=2, sticky="ew")
        self.show_button.grid(column=8, row=4)
        self.copy_button.grid(column=6, row=6, columnspan=2, sticky="ew")
        self.strength_label.grid(column=1, row=4, columnspan=4, rowspan=3, sticky="N")
    
    def toggle_show_password(self):
        
        
        if self.password_generated_var.get():
            
            # Shows or hides the password based on current state
            # Passwords are automatically hidden after generation
            if self.show_hide_text.get() == "Show":
                self.password_entry.config(show="")
                self.show_hide_text.set("Hide")
            else:
                self.password_entry.config(show="*")
                self.show_hide_text.set("Show")
        
        else:
            
            # Informs user they must generate a password before clickling "Show"
            messagebox.showinfo("Info", "Please generate a password first.")
            
    def copy_password(self):
        
        if self.password_generated_var.get():
        
            # Copies password to clipboard
            self.password_entry.clipboard_clear()
            self.password_entry.clipboard_append(self.password_entry.get())
        
            # Displays a message that password was succesfully copied
            messagebox.showinfo("Success", "Password copied to clipboard!")
            
        else:
            
            # Informs user they must generate a password before clicking "Copy"
            messagebox.showinfo("Info", "Please generate a password first.")
            
    def get_selected_char_sets(self):
        return [char_set for char_set, var in [(string.ascii_uppercase, self.uppercase_var),
                                              (string.ascii_lowercase, self.lowercase_var),
                                              (string.digits, self.digits_var),
                                              (string.punctuation, self.symbols_var)]
                                              if var.get()]
    
    def password_entropy(self, password):
        
        # Calculates password entropy
        entropy = 0
        length = len(password)
        char_set_len = len(set(password))
        entropy = length * math.log2(char_set_len)
        return entropy
        
    def check_password_strength(self, password):
        
        entropy = self.password_entropy(password)
        
        # Set strength based on entropy thresholds
        if entropy < 40:
            return "         VERY WEAK"
        elif entropy < 50:
            return "           WEAK"
        elif entropy < 60:
            return "          DECENT"
        elif entropy < 70:
            return "           GOOD"
        elif entropy < 80:
            return "          STRONG"
        elif entropy < 90:
            return "     VERY STRONG"
        else:
            return "  STUPID STRONG"
        
    def generate_password(self):
        
        # Enables "Show" and "Copy" buttons
        self.password_generated_var.set(True)
        
        # Aquires characters for passwords
        length = self.password_length_var.get()
        
        # Ensures password is an appropriate length
        if length < 8 or length > 32:
            messagebox.showerror("Error", "Password length must be between 8 and 32 characters.")
            return
        
        # Ensures password has atleast three different character types
        char_sets = self.get_selected_char_sets()
        if len(char_sets) < 3:
            messagebox.showerror("Error", "Please select at least three character sets.")
            return
        
        # Combines characters to form passowrds
        combined_chars = ''.join(char_sets)
        password = ''.join(random.choice(combined_chars) for _ in range(length))
        self.password_entry.delete(0, END)
        self.password_entry.insert(0, password)
        self.password_entry.config(show="*")
        
        # Sets the password strength of the password
        password_strength = self.check_password_strength(password)
        self.strength_label.config(text=f"\nPassword Strength:\n{password_strength}")
        
        # Resets the "Show" button
        self.password_entry.config(show="*")
        self.show_hide_text.set("Show")

root = Tk()
RandomPasswordGenerator(root)
root.mainloop()                     