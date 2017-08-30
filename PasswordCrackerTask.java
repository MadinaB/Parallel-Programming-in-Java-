package PasswordCracker;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static PasswordCracker.PasswordCrackerConsts.*;

//  Runnable class
// site : https://docs.oracle.com/javase/8/docs/api/java/lang/Runnable.html

public class PasswordCrackerTask implements Runnable {
    int taskId;
    boolean isEarlyTermination;
    PasswordFuture passwordFuture;
    PasswordCrackerConsts consts;

    public PasswordCrackerTask(int taskId, boolean isEarlyTermination, PasswordCrackerConsts consts, PasswordFuture passwordFuture) {
        this.taskId = taskId;
        this.isEarlyTermination = isEarlyTermination;
        this.consts = consts;
        this.passwordFuture = passwordFuture;
    }

    /* ### run ### */

    @Override
    public void run() {
       
        long range=consts.getPasswordSubRangeSize();  
        long rangeBegin=(taskId)*range;
        long rangeEnd=(taskId+1)*range-1;
        String password = findPasswordInRange(rangeBegin, rangeEnd, consts.getEncryptedPassword());
        //System.out.println("This is password "+password);
        if(password!=null){
        passwordFuture.set(password);}
    }

    /*	### findPasswordInRange	###
     * The findPasswordInRange method find the original password using md5 hash function
     * if a thread discovers the password, it returns original password string; otherwise, it returns null;
    */
    
    public String findPasswordInRange(long rangeBegin, long rangeEnd, String encryptedPassword) {
        
        String instance=null;
        MessageDigest messageDgst= getMessageDigest();
        int[] candidateChars=new int[consts.passwordLength];
        transformDecToBase36(rangeBegin,candidateChars);
        for(long i=rangeBegin;i<=rangeEnd;i++){                     //Include bounds.
            instance = transformIntToStr(candidateChars);
            String encryptedInstance=encrypt(instance, messageDgst);
       //       System.out.println(instance+" "+encryptedInstance+" "+encryptedPassword
       //             +" "+(encryptedInstance==encryptedPassword));
            if(!(encryptedInstance.equals(encryptedPassword)))
            {instance=null;}
            else{ return instance;}                                             // Password is found.
            getNextCandidate(candidateChars);
            if(isEarlyTermination==true){if(passwordFuture.isDone()){return null;}}
        }
        return null;

    }

    /* 
     * The transformDecToBase36 transforms decimal into numArray that is base 36 number system
     * 
    */
    private void transformDecToBase36(long numInDec, int[] numArrayInBase36) {
      
        long n=numInDec;
        for(int i=0;i<consts.passwordLength;i++){
            numArrayInBase36[consts.passwordLength-i-1]=(int)n%36;
            n=n/36;
        }
    }

    /*
     * The getNextCandidate update the possible password represented by 36 base system
    */

    private static boolean increment(int[] arr, int index) {
            arr[index]=arr[index]+1;
            if(arr[index]<=35){return false;}// no need in recurse
            else{
                arr[index]=0;
                return true;}
    }

    private static void getNextCandidate(int[] arr) {
        
        int i=arr.length-1;
        boolean recurse=increment(arr,i);
        while(recurse){
            if(i==0){break;}
            i=i-1; recurse=increment(arr,i);
        }

    }

    /*
     * We assume that each character can be represented to a number : 0 (0) , 1 (1), 2 (2) ... a (10), b (11), c (12), ... x (33), y (34), z (35)
     * The transformIntToStr transforms int-array into string (numbers and lower-case alphabets)
     * int array is password represented by base-36 system
     * return : password String
     *
     * For example,
     *     int[] pwdBase36 = {10, 11, 12, 13, 0, 1, 9, 2};
     *     String password = transfromIntoStr(pwdBase36);
     *     System.out.println(password);
     *     output is abcd0192.
     *
    */
    private static String transformIntToStr(int[] chars) {
        char[] password = new char[chars.length];
        for (int i = 0; i < password.length; i++) {
            password[i] = PASSWORD_CHARS.charAt(chars[i]);    
        }
        return new String(password);
    }


    public static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance("MD5");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Cannot use MD5 Library:" + e.getMessage());
        }
    }

    public static String encrypt(String password, MessageDigest messageDigest) {
        messageDigest.update(password.getBytes());
        byte[] hashedValue = messageDigest.digest();
        return byteToHexString(hashedValue);
    }

    public static String byteToHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                builder.append('0');
            }
            builder.append(hex);
        }
        return builder.toString();
    }
}



