

public class CTest{

    public static void main(String args[]) {
String str = "_ZN3DogC1EmmNSt7__cxx1112";
boolean b = presumClassMethod(str);

if (b)
System.out.println("it is ClassMethod");
else
System.out.println("it isnot ClassMethod");

str = "deregister_tm_clones";
b =  presumClassMethod(str);
if (b)
System.out.println("it is ClassMethod");
else
System.out.println("it isnot ClassMethod");
      
str = "_ZN3Dog10printSoundEv";
b =  presumClassMethod(str);
if (b)
System.out.println("it is ClassMethod");
else
System.out.println("it isnot ClassMethod"); 

str = "_zn3dog10printsoundev";
b =  presumClassMethod(str);
if (b)
System.out.println("it is ClassMethod");
else
System.out.println("it isnot ClassMethod");

    }

    static boolean presumClassMethod (String str) {
        boolean  isDash = false;
        boolean  isDigit = false;
        boolean  isUpcase = false;

        for (char ch : str.toCharArray()) {
            isDash |= (ch == '_');
            isDigit |= Character.isDigit(ch);
            isUpcase |= Character.isUpperCase(ch);
        }
        return isDash && isDigit && isUpcase;             
    }
}
