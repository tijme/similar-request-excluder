package excluder.sets;

import excluder.ExtensionDebugger;

import java.util.*;

public class OrderedHashSet implements Collection, Cloneable {

    public interface OrderedHashSetListener {
        void indexAdded(int start, int end);
        void indexChanged(int start, int end);
        void indexRemoved(int start, int end);
    }

    private HashSet objectsHash = new HashSet();

    private LinkedList objects = new LinkedList();

    private OrderedHashSetListener listener;

    public OrderedHashSet() {
        clear();
    }

    public void setListener(OrderedHashSetListener listener) {
        this.listener = listener;
    }

    public void clear() {
        int size = objects.size();

        objects.clear();
        objectsHash.clear();

        if (listener != null && size - 1 >= 0) {
            listener.indexRemoved(0, size - 1);
        }
    }

    public boolean add(Object o) {
        boolean newToList = objectsHash.add(o);

        if (!newToList) {
            objects.remove(o);
        }

        objects.add(o);

        if (listener != null) {
            if (newToList) {
                listener.indexAdded(objects.size() - 1, objects.size() - 1);
            } else {
                listener.indexChanged(objects.size() - 1, objects.size() - 1);
            }
        }

        return newToList;
    }

    public boolean remove(Object o) {
        if (objectsHash.remove(o)) {
            objects.remove(o);
            return true;
        }

        return false;
    }

    public boolean addAll(Collection c) {
        ExtensionDebugger.error("OrderedHashSet.addAll() is not implemented.");
        return false;

//        boolean mod = false;
//
//        for (Iterator iter = c.iterator(); iter.hasNext(); ) {
//            mod = add(iter.next()) || mod;
//        }
//
//        return mod;
    }

    public boolean contains(Object o) {
        return objectsHash.contains(o);
    }

    public boolean containsAll(Collection c) {
        ExtensionDebugger.error("OrderedHashSet.containsAll() is not implemented.");
        return false;

//        for (Iterator iter = c.iterator(); iter.hasNext(); ) {
//            if (!this.contains(iter.next())) {
//                return false;
//            }
//        }
//
//        return true;
    }

    public boolean removeAll(Collection c) {
        ExtensionDebugger.error("OrderedHashSet.removeAll() is not implemented.");
        return false;

//        boolean mod = false;
//
//        for (Iterator iter = c.iterator(); iter.hasNext(); ) {
//            mod = this.remove(iter.next()) || mod;
//        }
//
//        return mod;
    }

    public boolean retainAll(Collection c) {
        ExtensionDebugger.error("OrderedHashSet.retainAll() is not implemented.");
        return false;

//        boolean mod = false;
//
//        for (Iterator iter = this.iterator(); iter.hasNext(); ) {
//            Object o = iter.next();
//            if (!c.contains(o)) {
//                mod = this.remove(o) || mod;
//            }
//        }
//
//        return mod;
    }

    public boolean equals(Object o) {
        if (!(o instanceof OrderedHashSet)) {
            return false;
        }

        return objects.equals(((OrderedHashSet) o).objects);
    }

    public int hashCode() {
        return objectsHash.hashCode();
    }

    public boolean isEmpty() {
        return objects.isEmpty();
    }

    public Iterator iterator() {
        return objects.iterator();
    }

    public int size() {
        return objects.size();
    }

    public Object[] toArray() {
        return objects.toArray();
    }

    public Object[] toArray(Object[] a) {
        return objects.toArray(a);
    }

    public Object get(int index) {
        return objects.get(index);
    }

    public int indexOf(Object o) {
        return objects.indexOf(o);
    }

    public List toList() {
        return objects;
    }

}
