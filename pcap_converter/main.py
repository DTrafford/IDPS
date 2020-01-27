import os

startdir = '/Users/davidtrafford/Documents/School/IDPS/TEST/'
suffix= '.pcap'
outputdir = os.path.join(startdir, "data_set_csv")

for root, dirs, files, in os.walk(startdir):
    for name in files:
        if name.lower().endswith(suffix):
            print(name)
            sub_folders = root[len(startdir)+1:]

            input_filename = os.path.join(root, name)
            output_path = os.path.join(outputdir, sub_folders)
            os.makedirs(output_path, exist_ok=True)  # Ensure the output folder exists
            output_filename = os.path.join(output_path, os.path.splitext(name)[0] + '.csv')

            # cmd = 'tshark -r {} -T fields -e frame.number -e frame.time_relative -e wlan.sa -e wlan.da -e wlan.ta -e wlan.ra -e frame.time_delta_displayed -e frame.len -E header=y -E separator=, -E quote=d -E occurrence=f > {}'
            cmd = 'tshark -r {} -n -T fields -E separator=, -e frame.time -e ip.src -e ip.dst -e ip.proto -e tcp.port > {}'
            final_cmd = cmd.format(input_filename, output_filename)

            print(final_cmd)
            os.system(final_cmd)