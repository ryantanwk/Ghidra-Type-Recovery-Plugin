class Test
{
    private:
        int data1;
        float data2;  

    public:  
        void function1()
        {   data1 = 2;  } 

        float function2()
        { 
            data2 = 3.5;
            return data2;
        }
   };

int main()
{
    Test o1;

    o1.function1();
    o1.function2();

}
