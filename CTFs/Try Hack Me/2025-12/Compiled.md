Difficulty: Easy

Decompiling gives us following code:
``` C
undefined8 main(void)

{
  int iVar1;
  char local_28 [32];
  
  fwrite("Password: ",1,10,stdout);
  __isoc99_scanf("DoYouEven%sCTF",local_28);
  iVar1 = strcmp(local_28,"__dso_handle");
  if ((-1 < iVar1) && (iVar1 = strcmp(local_28,"__dso_handle"), iVar1 < 1)) {
    printf("Try again!");
    return 0;
  }
  iVar1 = strcmp(local_28,"_init");
  if (iVar1 == 0) {
    printf("Correct!");
  }
  else {
    printf("Try again!");
  }
  return 0;
}
```

The key lines are:
``` C
__isoc99_scanf("DoYouEven%sCTF",local_28);
```

and:
```C
iVar1 = strcmp(local_28,"_init");
```

`scanf()` reads until %s, so the password would be: en`DoYouEven_init` which is correct.