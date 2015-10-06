# various settings to make the graph readable
s/, fontsize=8/, fontname="Ariel", fontsize=8, overlap=prism, overlap_scaling=1/
s/penwidth=0/penwidth=1/
s/, label="" //      

# Non-local IPs get the octagon shape
s/shape=ellipse/shape=octagon/

# Local IPs get the ellipse shape
s/^\("172\.2[01]\..*\)]$/\1,shape=ellipse]/
s/^\("192\.168\..*\)]$/\1,shape=ellipse]/
s/^\("10\..*\)]$/\1,shape=ellipse]/

