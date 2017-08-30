package PasswordCracker;

import java.util.concurrent.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class PasswordCrackerMain {
    public static void main(String args[]) {
        if (args.length < 4) {
            System.out.println("Usage: PasswordCrackerMain numThreads passwordLength isEarlyTermination encryptedPassword");
            return;
        }
        int numThreads = Integer.parseInt(args[0]);
        int passwordLength = Integer.parseInt(args[1]);
        boolean isEarlyTermination = Boolean.parseBoolean(args[2]);
        String encryptedPassword = args[3];

       
        // refer to site: https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/ExecutorService.html
        
        ExecutorService workerPool = Executors.newFixedThreadPool(numThreads);
        PasswordFuture passwordFuture = new PasswordFuture();
        PasswordCrackerConsts consts = new PasswordCrackerConsts(numThreads, passwordLength, encryptedPassword);

	/*Create PasswordCrackerTask and use executor service to run in a separate thread*/

        for (int i = 0; i < numThreads; i++) {
            
           // System.out.println("Create worker");

            PasswordCrackerTask worker=new PasswordCrackerTask(i,isEarlyTermination, consts, passwordFuture);
            workerPool.submit(worker);
        }

        try {
            System.out.println("20162014");
            System.out.println(numThreads);
            System.out.println(passwordLength);
            System.out.println(isEarlyTermination);
            System.out.println(encryptedPassword);
            System.out.println("Password: " + passwordFuture.get());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            workerPool.shutdown();
        }
    }
}

/**
 * A {@code Future} represents the result of an asynchronous
 * computation.  Methods are provided to check if the computation is
 * complete, to wait for its completion, and to retrieve the result of
 * the computation.  The result can only be retrieved using method
 * {@code get} when the computation has completed, blocking if
 * necessary until it is ready.  Cancellation is performed by the
 * {@code cancel} method.  Additional methods are provided to
 * determine if the task completed normally or was cancelled. Once a
 * computation has completed, the computation cannot be cancelled.
 * If you would like to use a {@code Future} for the sake
 * of cancellability but not provide a usable result, you can
 * declare types of the form {@code Future<?>} and
 * return {@code null} as a result of the underlying task.
 **/
//  https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/Future.html


class PasswordFuture implements Future<String> {
    String result;
    Lock lock = new ReentrantLock();
    Condition resultSet = lock.newCondition();
    
    
    // Condition and Lock class in javadoc

    /*  ### set ###
     *  set the result and send signal to thread waiting for the result
     */

    public void set(String result) {
        lock.lock();
        try{this.result=result;
            resultSet.signalAll();
          //  if(isDone()){return ;}
        }
        finally{lock.unlock();}

    }

    /*  ### get ###
     *  if result is ready, return it.
     *  if not, wait on the conditional variable.
     */
    @Override
    public String get() throws InterruptedException, ExecutionException {
        
        // return this.result;

        lock.lock();
        try{
            while(result==null){resultSet.await();}
            return result;
        }
        finally{lock.unlock();}

    }
    /*  ### isDone ###
     *  returns true if result is set
     */
    @Override
    public boolean isDone() {
        if(result!=null){return true;}
        else{return false;}

    }


    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        return false;
    }
    @Override
    public boolean isCancelled() {
        return false;
    }
    @Override
    public String get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        return null;
    }
}


