import com.google.gson.Gson;
import java.util.*;
import java.io.FileReader;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONTokener;

public class DebugJSON {
    public static void main(String[] args) throws Exception {
        // Read test payloads
        FileReader reader = new FileReader("/shared/test-payloads.json");
        JSONObject root = new JSONObject(new JSONTokener(reader));
        JSONArray testCases = root.getJSONArray("test_cases");
        
        // Find large_payload
        JSONObject largePayload = null;
        for (int i = 0; i < testCases.length(); i++) {
            JSONObject tc = testCases.getJSONObject(i);
            if ("large_payload".equals(tc.getString("name"))) {
                largePayload = tc.getJSONObject("body");
                break;
            }
        }
        
        if (largePayload != null) {
            // Convert to Map using Gson
            Gson gson = new Gson();
            Map<String, Object> bodyMap = gson.fromJson(largePayload.toString(), Map.class);
            
            // Sort recursively
            Map<String, Object> sorted = sortMapRecursively(bodyMap);
            
            // Serialize
            String json = gson.toJson(sorted);
            json = json.replaceAll("\":", "\": ").replaceAll(",\"", ", \"").replaceAll("\\},\\{" , "}, {");
            
            System.out.println("Java JSON:");
            System.out.println(json);
            System.out.println("\nLength: " + json.length());
        }
    }
    
    private static Map<String, Object> sortMapRecursively(Map<String, Object> map) {
        Map<String, Object> sorted = new TreeMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                sorted.put(entry.getKey(), sortMapRecursively((Map<String, Object>) value));
            } else if (value instanceof java.util.List) {
                java.util.List<?> list = (java.util.List<?>) value;
                java.util.List<Object> sortedList = new java.util.ArrayList<>();
                for (Object item : list) {
                    if (item instanceof Map) {
                        sortedList.add(sortMapRecursively((Map<String, Object>) item));
                    } else {
                        sortedList.add(item);
                    }
                }
                sorted.put(entry.getKey(), sortedList);
            } else {
                sorted.put(entry.getKey(), value);
            }
        }
        return sorted;
    }
}
