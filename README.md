This is our custom GOOSE injection attack tool. 
SETUP:

1) Download Zip File
2) Extract Zip File into desired output location
3) Choose between our 3 GUI options 
3A) most updated version is "LATEST_simplified_with_interface_option"
4) Run the main method
5) to make executables for other versions follow the directions:
   
a. Install required dependancies

b. Install the pyinstaller module (at time of writing I was using 6.4.0)

c. In command prompt, navigate to the directory which contains main.py
-This should be inside of "attack_tool_web-master"

d. Run the following command: pyinstaller -F --add-data "templates;templates" --add-data "static;static" --add-data "lib;lib" main.py

e. You should see a "build" and "dist" folder created in the current directory. The exe will be contained in the "dist" folder.
