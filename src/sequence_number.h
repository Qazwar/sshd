#ifndef _SEQUENCE_NUMBER_H_
#define _SEQUENCE_NUMBER_H_

namespace ssh
{
    /* Class:           sequence_number
     * Description:     
     */
    template<class T>
    class sequence_number
    {
    public:
        sequence_number() : val(0) 
        {
        }

        T update() {return val++;}
    protected:
        T val;
    };
};

#endif