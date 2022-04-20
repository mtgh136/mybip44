package com.zh.coinutil.bip44;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MnemUtils {
  public final static String Local_En = "en";
  public final static String Local_Zh_Cn = "zh_cn";

  private final static Map<String, List<String>> wordsMap = new HashMap<>();

  private final static Map<String, Map<String, Integer>> wordIdxMap = new HashMap<>();

  static {
    wordsMap.put(Local_En, loadWords(Local_En));
  }

  private static void initIdxMap(String local, List<String> ws) {
    Map<String, Integer> tmpWordIdxMap = new HashMap<>();
    int len = ws.size();
    for (int i = 0; i < len; i++) {
      tmpWordIdxMap.put(ws.get(i), i);
    }
    wordIdxMap.put(local, tmpWordIdxMap);
  }

  private static List<String> loadWords(String local) {
    String name = local + ".txt";
    InputStream is = ClassLoader.getSystemResourceAsStream("bip44mnem/" + name);
    if (is == null) {
      return null;
    }
    List<String> rtn = readAllLines(is);
    initIdxMap(local, rtn);
    return rtn;
  }

  private static List<String> readAllLines(InputStream inputStream) {
    try {
      BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
      List<String> data = new ArrayList<>();
      for (String line; (line = br.readLine()) != null; ) {
        data.add(line);
      }
      br.close();
      return data;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static Map<String, Integer> getWordsIdx(String local) {
    getWords(local);
    return wordIdxMap.get(local);
  }

  private static List<String> getWords(String local) {
    List<String> rtn = wordsMap.get(local);
    if (rtn == null) {
      rtn = loadWords(local);
      wordsMap.put(local, rtn);
    }
//    if (rtn == null) {
//      rtn = wordsMap.get(Local_En);
//    }
    return rtn;
  }

  public static String localMnemToEn(String mnem, String local) {
    return mnemTo(mnem, local, Local_En);
  }

  public static String enMnemToLocal(String mnem, String local) {
    return mnemTo(mnem, Local_En, local);
  }

  private static String mnemTo(String mnem, String from, String to) {
    List<String> lWords = getWords(to);
    if (lWords == null) { //没有对应语言助记词,返回原来的
      return mnem;
    }
    Map<String, Integer> tmpWordIdxMap = getWordsIdx(from);
    if (tmpWordIdxMap == null) {
      return mnem;
    }
    String[] ws = mnem.split(" ");
    String[] rtn = new String[ws.length];
    for (int i = 0; i < ws.length; i++) {
      rtn[i] = lWords.get(tmpWordIdxMap.get(ws[i]));
    }
    return String.join(" ", rtn);
  }
}
