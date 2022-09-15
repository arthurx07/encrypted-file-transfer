from time import sleep
j=0
k='#'
def fixed_space(i,array):
    g=(' '*len(str(len(array))))
    g=g.replace(' ','',len(str(int(i))))
    return g
def ani(i,array):
    global k
    #For accessing the global variables that are defined out of the function
    global j
    per=((i+1)*100)//len(array)
    #To calculate percentage of completion of loop
    c=per//5
    #Integer division (the value 5 decides the length of the bar)
    if c!=j:
    #When ever the values of these 2 variables change add one # to the global variable k
        k+='#'
    y='['+k+'                     '+']'
    #20 empty spaces (100/5) 
    y=y.replace(' ','',len(k))
    #To make the size of the bar fixed ever time the length of k increases one ' ' will be removed
    g=fixed_space(per,array)
    #To fix at the same position
    f=fixed_space(i,array)
    print('Status : ',y,g+str(per)+'%',' ('+f+str(i+1)+' / '+str(len(array))+' ) ',end='\r')
    #That same '\r' to clear previous text
    j=c

array = range(100)
for i in array:
    ani(i,array)
    sleep(0.1)
